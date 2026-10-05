// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_runtime.ts
//
// ---------------------------------------------------------------------------
// THE STATIC CONSOLE'S RUNTIME (#446, step 5).
//
// The console in the browser: it signs in as the public client
// `sts-admin-console`, holds its tokens in memory, sends every request with
// a DPoP proof, draws every page from its `/admin-api` answer with the
// renderers `web_pages.ts` registers, and sends every form to the operation
// that mirrors it. What it does, in the order a page load meets it:
//
//   * SIGN-IN (rcbj's decision 1 on #446): the authorization code flow with
//     PKCE (S256) at the authorization server of the realm the console was
//     opened in — the realm of the URL, as the server-rendered console's
//     flow ran, so a sign-on session the portal holds answers it — with
//     `resource` naming that realm's `/admin-api`. The verifier, the state
//     and the page to come back to cross the redirect in sessionStorage,
//     which holds no credential; the TOKENS are held in this object only
//     and a full reload signs in again (silently, while the sign-on session
//     lasts).
//   * DPoP (RFC 9449), mandatory for this client: one P-256 key per page
//     load, generated NON-EXTRACTABLE, so script can sign with it and
//     nothing can copy it out. Every token request and every API request
//     carries a proof; an API proof carries `ath`; a server's `DPoP-Nonce`
//     is kept and a `use_dpop_nonce` refusal is retried once with it. The
//     refresh token is bound to the same key and rotated on every use.
//   * ROUTING on the console's own paths and queries, so a deep link and the
//     browser's history work as they did: a same-origin link under the
//     realm's `/admin` is followed in place, the page drawn from
//     `WebPages.render()` inside `WebShell.frame()` (the shell answer is
//     `GET /admin-api/console`, fetched once per realm).
//   * FORMS: a GET form navigates; a POST form goes to the operation
//     `WebForms.resolve()` names (a form it names none for is REFUSED, not
//     guessed), and its answer is drawn as the server-rendered console drew
//     it — the page again with the notice, the refusal in the strip, a
//     revealed credential on the page that asked, a file saved.
//   * THE REALM SWITCHER moves to another realm's pages in place, keeping
//     the token: a default-realm token's audience is accepted in every
//     realm (`AdminApi.wantedAudiences()`).
//
// Everything it touches in the browser — `fetch`, `crypto`, `location`,
// `history`, `document`, `sessionStorage` — arrives through the
// constructor, so a test drives it in node with stand-ins.
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires other `web_` modules
// only, logs nothing, and is bundled for a browser by `build-typescript.sh`.
// Unlike the renderers it HOLDS STATE — the tokens, the key, the nonce, the
// shell — which is what a runtime is, and it holds it in one instance.
// ---------------------------------------------------------------------------

import kit = require('./web_kit');
import WebPages = require('./web_pages');
import WebShell = require('./web_shell');
import WebForms = require('./web_forms');

type Json = any;

// The console's client: public, DPoP-bound (`sender_constraints.ts`,
// `DPOP_BOUND_PUBLIC_CLIENTS`).
const CLIENT_ID = 'sts-admin-console';
// What it asks for: an ID Token for who signed in, and the two scopes the
// management API takes, narrowed at issuance to the roles the person holds.
const SCOPE = 'openid admin:read admin:write';
// The key the sign-in's one-use values cross the redirect under.
const SIGNIN_KEY = 'sts-console-signin';
// How long before an access token's expiry it is refreshed, in seconds.
const REFRESH_EARLY = 30;

/**
 * The static console's runtime: sign-in, DPoP, routing and forms.
 */
class ConsoleRuntime {
  private env: Json;
  private prefix: string;
  private accessToken: string;
  private refreshToken: string;
  private expiresAt: number;
  private key: Json;
  private publicJwk: Json;
  private nonce: string;
  private shell: Json;
  private shellPrefix: string;
  private me: Json;
  private formTable: Json;
  private view: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects: `fetch`, `crypto` (WebCrypto),
   *   `location`, `history`, `document`, `sessionStorage`, `navigator`,
   *   `window`, and, for a test, `now` (milliseconds; `Date.now` where left
   *   out) and `formDataOf` (a form's FormData)
   */
  constructor(env: Json) {
    this.env = env;
    this.prefix = ConsoleRuntime.prefixOf(env.location.pathname);
    this.accessToken = '';
    this.refreshToken = '';
    this.expiresAt = 0;
    this.key = null;
    this.publicJwk = null;
    this.nonce = '';
    this.shell = null;
    this.shellPrefix = '';
    this.me = null;
    this.formTable = null;
    this.view = null;
  }

  // --- paths ---------------------------------------------------------------

  /**
   * Splits a path at the console: the realm prefix before `/admin`.
   *
   * @param pathname - a path, `/realm/acme/admin/users` or `/admin`
   * @returns the prefix, '' in the default realm
   */
  static prefixOf(pathname: string): string {
    const m = /^(.*?)\/admin(?:\/.*)?$/.exec(String(pathname || ''));
    return m ? m[1] : '';
  }

  /**
   * The console path of a full path under this realm, or null for one that
   * is not a console page.
   *
   * @param pathname - the path
   * @returns `/admin...` without the prefix, or null
   */
  consolePath(pathname: string): string | null {
    const path = String(pathname || '');
    if (path.indexOf(this.prefix + '/admin') !== 0) {
      return null;
    }
    const rest = path.slice(this.prefix.length);
    if (!/^\/admin(\/|$)/.test(rest) || /^\/admin-api(\/|$)/.test(rest)) {
      return null;
    }
    return rest;
  }

  /**
   * Parses a query string into an object, the last value of a repeated
   * name winning as express's own parser does for a single value.
   *
   * @param search - `?a=1&b=2` or ''
   * @returns the query
   */
  static queryOf(search: string): Json {
    const out = {};
    new URLSearchParams(String(search || '').replace(/^\?/, ''))
      .forEach(function (value, name) {
        out[name] = value;
      });
    return out;
  }

  // --- encoding and crypto -------------------------------------------------

  /**
   * Base64url without padding.
   *
   * @param bytes - the bytes
   * @returns the encoding
   */
  static b64u(bytes: Uint8Array): string {
    let s = '';
    for (let i = 0; i < bytes.length; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Random bytes, base64url.
   *
   * @param n - how many bytes
   * @returns the encoding
   */
  random(n: number): string {
    const bytes = new Uint8Array(n);
    this.env.crypto.getRandomValues(bytes);
    return ConsoleRuntime.b64u(bytes);
  }

  /**
   * SHA-256 of a string, base64url.
   *
   * @param text - the string
   * @returns the digest's encoding
   */
  async sha256(text: string): Promise<string> {
    const digest = await this.env.crypto.subtle.digest('SHA-256',
      new TextEncoder().encode(text));
    return ConsoleRuntime.b64u(new Uint8Array(digest));
  }

  // THE KEY IS MADE NON-EXTRACTABLE, which is the condition rcbj attached
  // to a public console: the private key can sign and cannot be exported, so
  // a script that reads this page can use the key while the page lives and
  // cannot carry it away. Only the public half is exported, for the proof's
  // header.
  /**
   * Makes this page load's DPoP key, once.
   *
   * @returns nothing
   */
  async ensureKey(): Promise<void> {
    if (this.key) {
      return;
    }
    const pair = await this.env.crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const jwk = await this.env.crypto.subtle.exportKey('jwk',
                                                         pair.publicKey);
    this.key = pair;
    this.publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  }

  // RFC 9449 section 4.2: `typ` dpop+jwt, the public key in the header, and
  // `jti`, `htm`, `htu` (no query, no fragment), `iat`, `ath` with an access
  // token and `nonce` once a server has given one. WebCrypto's ECDSA
  // signature is r || s, which is JOSE's ES256 form already.
  /**
   * Makes a DPoP proof for one request.
   *
   * @param method - the request's method
   * @param url - the request's URL; its query and fragment are dropped
   * @param accessToken - the access token it is sent with, or ''
   * @returns the proof
   */
  async proof(method: string, url: string,
              accessToken: string): Promise<string> {
    await this.ensureKey();
    const now = this.env.now ? this.env.now() : Date.now();
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: this.publicJwk };
    const claims: Json = {
      jti: this.random(16), htm: method.toUpperCase(),
      htu: String(url).replace(/[?#].*$/, ''), iat: Math.floor(now / 1000)
    };
    if (accessToken) {
      claims.ath = await this.sha256(accessToken);
    }
    if (this.nonce) {
      claims.nonce = this.nonce;
    }
    const enc = function (obj) {
      return ConsoleRuntime.b64u(new TextEncoder().encode(
        JSON.stringify(obj)));
    };
    const input = enc(header) + '.' + enc(claims);
    const signature = await this.env.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, this.key.privateKey,
      new TextEncoder().encode(input));
    return input + '.' + ConsoleRuntime.b64u(new Uint8Array(signature));
  }

  // --- the authorization server --------------------------------------------

  /**
   * This realm's address for one of its paths.
   *
   * @param path - `/oauth2/token`, `/admin-api/...`
   * @returns the absolute URL
   */
  url(path: string): string {
    return this.env.location.origin + this.prefix + path;
  }

  // The resource this console's tokens are for: the management API of the
  // realm it signed in at (`AdminApi.wantedAudiences()` and
  // `realmAudienceAccepted()` say which audiences it accepts).
  /**
   * The management API this console's tokens are audienced to.
   *
   * @returns the resource indicator
   */
  resource(): string {
    return this.url('/admin-api');
  }

  /**
   * Sends the browser to sign in, remembering where to come back to.
   *
   * @param returnTo - the path and query to land on after
   * @returns nothing
   */
  async beginSignIn(returnTo: string): Promise<void> {
    const verifier = this.random(32);
    const state = this.random(16);
    this.env.sessionStorage.setItem(SIGNIN_KEY, JSON.stringify({
      verifier: verifier, state: state, returnTo: returnTo,
      prefix: this.prefix }));
    const params = new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: this.url('/admin/callback'), scope: SCOPE,
      state: state, code_challenge: await this.sha256(verifier),
      code_challenge_method: 'S256', resource: this.resource()
    });
    this.env.location.assign(this.url('/oauth2/authorize') + '?' +
                             params.toString());
  }

  // A token endpoint answer with `error: use_dpop_nonce` is retried once
  // with the nonce it sent (RFC 9449 section 8).
  /**
   * Posts a form to the token endpoint with a DPoP proof.
   *
   * @param form - the form fields
   * @returns the response's JSON and status
   */
  async tokenRequest(form: Json): Promise<Json> {
    const endpoint = this.url('/oauth2/token');
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.env.fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                   'DPoP': await this.proof('POST', endpoint, '') },
        body: new URLSearchParams(form).toString()
      });
      this.keepNonce(res);
      const json = await res.json().catch(function () {
        return {};
      });
      if (res.status === 400 && json.error === 'use_dpop_nonce' &&
          attempt === 0) {
        continue;
      }
      return { status: res.status, json: json };
    }
    return { status: 400, json: { error: 'use_dpop_nonce' } };
  }

  /**
   * Keeps the tokens a token endpoint answered with.
   *
   * @param json - the token response
   * @returns nothing
   */
  keepTokens(json: Json): void {
    const now = this.env.now ? this.env.now() : Date.now();
    this.accessToken = String(json.access_token || '');
    // ROTATED: a refresh answers a new refresh token, and the old one is
    // spent. One that answered none keeps the one in hand.
    if (json.refresh_token) {
      this.refreshToken = String(json.refresh_token);
    }
    this.expiresAt = now + (Number(json.expires_in) || 300) * 1000;
  }

  /**
   * Keeps the nonce a response carried, for the next proof.
   *
   * @param res - a fetch response
   * @returns nothing
   */
  keepNonce(res: Json): void {
    const nonce = res && res.headers && res.headers.get
      ? res.headers.get('DPoP-Nonce') : '';
    if (nonce) {
      this.nonce = nonce;
    }
  }

  /**
   * Finishes a sign-in on the callback: checks the state, redeems the code
   * with the verifier and a proof, and goes where the sign-in began.
   *
   * @returns nothing
   */
  async finishSignIn(): Promise<void> {
    const query = ConsoleRuntime.queryOf(this.env.location.search);
    let saved: Json = null;
    try {
      saved = JSON.parse(this.env.sessionStorage.getItem(SIGNIN_KEY) || 'null');
    } catch (e) {
      // A value that is not JSON is no sign-in this page started, which the
      // state check below then says.
      saved = { unreadable: String((e && e.message) || e) };
    }
    this.env.sessionStorage.removeItem(SIGNIN_KEY);
    if (query.error) {
      this.drawProblem('Signing in was refused',
        String(query.error_description || query.error));
      return;
    }
    if (!saved || saved.unreadable || !query.code ||
        query.state !== saved.state) {
      this.drawProblem('This sign-in cannot be finished',
        'The answer from the authorization server does not belong to a ' +
        'sign-in this page started. Open the console again to sign in.');
      return;
    }
    const answer = await this.tokenRequest({
      grant_type: 'authorization_code', code: query.code,
      redirect_uri: this.url('/admin/callback'), client_id: CLIENT_ID,
      code_verifier: saved.verifier, resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.drawProblem('Signing in failed',
        String(answer.json.error_description || answer.json.error ||
               'The token endpoint answered ' + answer.status + '.'));
      return;
    }
    this.keepTokens(answer.json);
    const to = String(saved.returnTo || '/admin');
    this.env.history.replaceState(null, '', this.prefix + to);
    await this.route();
  }

  /**
   * Swaps the refresh token for a new pair, with a proof by the same key.
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

  // --- the management API --------------------------------------------------

  // Bearer is never sent: a token issued to this client is DPoP-bound and
  // `/admin-api` refuses one presented as Bearer (STS-OAUTH-0944). A 401
  // asking for a nonce is retried with it, an expired token is refreshed
  // and retried, and anything else unauthenticated starts a sign-in.
  /**
   * Calls the management API.
   *
   * @param method - GET or POST
   * @param path - the path under the realm, `/admin-api/...` with its query
   * @param body - for a POST: an object (sent as JSON) or a FormData
   * @returns the response
   */
  async api(method: string, path: string, body?: Json): Promise<Json> {
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.accessToken && now > this.expiresAt - REFRESH_EARLY * 1000) {
      await this.refresh();
    }
    if (!this.accessToken) {
      await this.beginSignIn(this.here());
      return null;
    }
    const target = this.url(path);
    for (let attempt = 0; attempt < 3; attempt++) {
      const headers: Json = {
        'Authorization': 'DPoP ' + this.accessToken,
        'DPoP': await this.proof(method, target, this.accessToken),
        'Accept': 'application/json'
      };
      let payload = undefined;
      if (body !== undefined && body !== null) {
        if (typeof FormData !== 'undefined' && body instanceof FormData) {
          payload = body;
        } else {
          headers['Content-Type'] = 'application/json';
          payload = JSON.stringify(body);
        }
      }
      const res = await this.env.fetch(target, { method: method,
                                                 headers: headers,
                                                 body: payload });
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
    await this.beginSignIn(this.here());
    return null;
  }

  /**
   * Calls the management API and reads its JSON.
   *
   * @param method - GET or POST
   * @param path - the path under the realm
   * @param body - for a POST, the body
   * @returns the status and the JSON, or null when a sign-in began
   */
  async apiJson(method: string, path: string, body?: Json): Promise<Json> {
    const res = await this.api(method, path, body);
    if (!res) {
      return null;
    }
    const json = await res.json().catch(function () {
      return null;
    });
    return { status: res.status, json: json, res: res };
  }

  // --- drawing -------------------------------------------------------------

  /**
   * The path and query being shown, without the realm prefix.
   *
   * @returns `/admin/...?...`
   */
  here(): string {
    const path = this.consolePath(this.env.location.pathname) || '/admin';
    return path + (this.env.location.search || '');
  }

  // The shell answer belongs to a realm (its sections, its chooser, its
  // banners), so it is fetched again when the realm changes; and the
  // operation table, which is the same everywhere, once.
  /**
   * Fetches what every page needs once: the shell and the form table.
   *
   * @returns whether they are in hand
   */
  async ensureShell(): Promise<boolean> {
    if (!this.shell || this.shellPrefix !== this.prefix) {
      const shell = await this.apiJson('GET', '/admin-api/console');
      if (!shell || shell.status !== 200) {
        return false;
      }
      this.shell = shell.json;
      this.shellPrefix = this.prefix;
      const me = await this.apiJson('GET', '/admin-api/me');
      this.me = me && me.status === 200 ? me.json : {};
    }
    if (!this.formTable) {
      const index = await this.apiJson('GET', '/admin-api');
      if (!index || index.status !== 200) {
        return false;
      }
      this.formTable = WebForms.table(index.json.operations || []);
    }
    return true;
  }

  // The page's frame from the shell, its body from the renderer, and the
  // notice or refusal a just-finished act left in the query on top, as the
  // server's `messagesOf()` drew it.
  /**
   * Draws a body inside the console's frame.
   *
   * @param title - the page's title
   * @param active - the console path that marks the nav
   * @param inner - the body
   * @param up - a drill-down's way up, or null
   * @returns nothing
   */
  draw(title: string, active: string, inner: string, up: Json): void {
    const query = ConsoleRuntime.queryOf(this.env.location.search);
    const notice = String(query.notice || '').slice(0, 500);
    const error = String(query.error || '').slice(0, 500);
    const messages = kit.flash((notice ? '<div class="ok">' +
                                kit.esc(notice) + '</div>' : '') +
                               (error ? '<div class="err">' +
                                kit.esc(error) + '</div>' : ''));
    const shell = this.shell || { gate: null, sections: [], realm: { id: '',
      name: '' }, navLabels: {}, version: {}, persistence: {} };
    this.env.document.title = title + ' — IYA STS admin';
    this.env.document.body.innerHTML = WebShell.frame(shell, {
      title: title, active: active, up: up, inner: messages + inner,
      path: this.here() });
    this.wireCopyButtons();
  }

  /**
   * Draws a page that says something went wrong, with no frame.
   *
   * @param title - what went wrong
   * @param detail - the detail
   * @returns nothing
   */
  drawProblem(title: string, detail: string): void {
    this.env.document.title = title + ' — IYA STS admin';
    this.env.document.body.innerHTML = '<div class="shell"><div ' +
      'class="main"><div class="card"><h1>' + kit.esc(title) + '</h1>' +
      kit.note(kit.esc(detail)) + '<p><a href="' +
      kit.esc(this.prefix + '/admin') + '">Open the console</a></p>' +
      '</div></div></div>';
  }

  // The page row by its path; a drill-down is the same row with its
  // parameter set, drawn by the row's own `drill`. A drill-down's way up is
  // what `AdminConsole.upTo()` gave: the section, with the list's own state.
  /**
   * Draws the page the location names.
   *
   * @returns nothing
   */
  async route(): Promise<void> {
    const path = this.consolePath(this.env.location.pathname);
    if (path === '/admin/callback') {
      await this.finishSignIn();
      return;
    }
    if (!this.accessToken) {
      await this.beginSignIn(this.here());
      return;
    }
    if (!await this.ensureShell()) {
      return;
    }
    const query = ConsoleRuntime.queryOf(this.env.location.search);
    const page = WebPages.PAGES.filter(function (row) {
      return row.path === path;
    })[0];
    if (!page) {
      this.draw('Not a console page', path || '/admin',
        kit.note('<code>' + kit.esc(path || '') + '</code> is not a page of ' +
                 'this console.'), null);
      return;
    }
    const opQuery = WebPages.operationQuery(page.path, query);
    const qs = new URLSearchParams(opQuery).toString();
    const answer = await this.apiJson('GET', page.operation +
                                      (qs ? '?' + qs : ''));
    if (!answer) {
      return;
    }
    if (answer.status !== 200 || !answer.json) {
      this.draw(page.title, page.path, kit.warn('The management API ' +
        'answered ' + answer.status + ' for <code>' +
        kit.esc(page.operation) + '</code>.' +
        (answer.json && answer.json.error
          ? ' ' + kit.esc(answer.json.error_description ||
                          answer.json.error) : ''), 'It could not be drawn'),
        null);
      return;
    }
    this.view = { page: page, json: answer.json, query: query };
    this.drawView(null);
  }

  /**
   * Draws the page in hand again, with what a just-finished act left.
   *
   * @param state - for the page's view: what the act answered, or null
   * @returns nothing
   */
  drawView(state: Json): void {
    const page = this.view.page;
    const query = this.view.query;
    const json = state
      ? Object.assign({}, this.view.json, { state: state })
      : this.view.json;
    const write = !!(this.me && this.me.write);
    const ctx = kit.context(query, write);
    const drilled = page.drill && query[page.drill.param];
    const up = drilled
      ? { href: page.path + kit.queryWith(kit.listViewOf(page.path, query),
                                          {}),
          label: (this.shell.navLabels || {})[page.path] || page.title,
          leaf: String(query[page.drill.param]),
          filtered: Object.keys(kit.listViewOf(page.path, query)).length > 0 }
      : null;
    this.draw(drilled ? page.title + ' ' + query[page.drill.param]
                      : page.title,
              page.path, WebPages.render(page.path, json, ctx), up);
  }

  /**
   * Goes to a console path, adding it to the history.
   *
   * @param to - the path and query under the realm, `/admin/...`
   * @returns nothing
   */
  async go(to: string): Promise<void> {
    this.env.history.pushState(null, '', this.prefix + to);
    await this.route();
  }

  // --- forms and links -----------------------------------------------------

  /**
   * A form's FormData — through `env.formDataOf` where a test hands one in.
   *
   * @param form - the form element
   * @returns its FormData
   */
  formDataOf(form: Json): Json {
    return this.env.formDataOf ? this.env.formDataOf(form)
                               : new FormData(form);
  }

  /**
   * A form's fields as an object: a name that repeats is an array, as the
   * console's own body parser reads it.
   *
   * @param data - the form's FormData
   * @returns the fields
   */
  static fieldsOf(data: Json): Json {
    const out = {};
    data.forEach(function (value, name) {
      if (Object.prototype.hasOwnProperty.call(out, name)) {
        out[name] = [].concat(out[name], [value]);
      } else {
        out[name] = value;
      }
    });
    return out;
  }

  // WHAT AN ACT'S ANSWER DRAWS, as `respondToAction()` drew it: the page the
  // form was on, again, with `notice` or `error` in the strip — and, for
  // the two kinds of answer that page would otherwise lose, the credential
  // a reveal handed back (drawn on the page that asked, never in a URL)
  // and a file (saved, never drawn).
  /**
   * Sends a POST form to the operation that mirrors it and draws the answer.
   *
   * @param form - the form element
   * @param submitter - the button that submitted it, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const page = this.consolePath(target.pathname);
    const data = this.formDataOf(form);
    if (submitter && submitter.name) {
      data.append(submitter.name, submitter.value);
    }
    const fields = ConsoleRuntime.fieldsOf(data);
    const action = Array.isArray(fields.action) ? fields.action[0]
                                                : String(fields.action || '');
    const operation = page ? WebForms.resolve(this.formTable, page, action)
                           : null;
    const back = this.here().replace(/([?&])(notice|error)=[^&]*/g, '$1')
                            .replace(/[?&]+$/, '');
    if (!operation) {
      await this.go(back + (back.indexOf('?') < 0 ? '?' : '&') +
        'error=' + encodeURIComponent('This control has no /admin-api ' +
        'operation (' + (page || target.pathname) + ' ' + action + '), so ' +
        'the static console refuses it rather than guess.'));
      return;
    }
    const multipart = /multipart\/form-data/i.test(
      String(form.getAttribute('enctype') || ''));
    const res = await this.api('POST', operation, multipart ? data : fields);
    if (!res) {
      return;
    }
    const disposition = String((res.headers && res.headers.get &&
                                res.headers.get('Content-Disposition')) || '');
    if (/attachment/i.test(disposition)) {
      await this.save(res, disposition);
      return;
    }
    const json = await res.json().catch(function () {
      return { ok: res.status < 400 };
    });
    if (json && json.ok && action === 'reveal-secret' && this.view) {
      this.drawView({ revealed: { secret: fields.secret,
                                  value: json.value } });
      return;
    }
    const key = json && json.ok ? 'notice' : 'error';
    const message = json && json.ok
      ? String(json.message || 'Done.')
      : ((json && json.errors) || []).join(' ') ||
        String((json && (json.why || json.error_description ||
                         json.error)) || 'Refused.');
    await this.go(back + (back.indexOf('?') < 0 ? '?' : '&') + key + '=' +
                  encodeURIComponent(message));
  }

  /**
   * Saves a response the server said is a file.
   *
   * @param res - the response
   * @param disposition - its Content-Disposition
   * @returns nothing
   */
  async save(res: Json, disposition: string): Promise<void> {
    const name = (/filename="?([^";]+)"?/i.exec(disposition) || [])[1] ||
      'download';
    const blob = await res.blob();
    const href = URL.createObjectURL(blob);
    const a = this.env.document.createElement('a');
    a.href = href;
    a.download = name;
    this.env.document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(href);
  }

  // THE REALM SWITCHER, in place: the server's `/admin/realm-switch` moved
  // the browser to the realm's prefix; here the prefix changes and the page
  // is drawn again, with the token in hand.
  /**
   * Switches to another realm's copy of a console path.
   *
   * @param realmId - the realm
   * @param to - the console path and query to show there
   * @returns nothing
   */
  async switchRealm(realmId: string, to: string): Promise<void> {
    const realm = (this.shell && this.shell.realms || []).filter(
      function (one) {
        return one.id === realmId;
      })[0];
    if (!realm) {
      return;
    }
    this.prefix = String(realm.prefix || '');
    await this.go(String(to || '/admin'));
  }

  /**
   * Follows a link in place when it is a console page of this origin.
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
    if (url.origin !== this.env.location.origin) {
      return;
    }
    const page = this.consolePath(url.pathname);
    if (!page || url.search.indexOf('format=') >= 0) {
      return;
    }
    event.preventDefault();
    if (url.pathname === this.env.location.pathname &&
        url.search === this.env.location.search && url.hash) {
      this.env.location.hash = url.hash;
      return;
    }
    this.go(page + url.search).then(function () {
      if (url.hash) {
        const target = el.ownerDocument.getElementById(url.hash.slice(1));
        if (target && target.scrollIntoView) {
          target.scrollIntoView();
        }
      }
    });
  }

  // A GET form navigates to its query (the realm switcher is one, and is
  // answered in place); a POST form is an act. A form whose action is not a
  // console page — the sign-in screen, the portal — is left to the browser.
  /**
   * Handles a submitted form.
   *
   * @param event - the submit event
   * @returns nothing
   */
  onSubmit(event: Json): void {
    const form = event.target;
    const target = new URL(form.getAttribute('action') || this.here(),
                           this.env.location.href);
    const page = this.consolePath(target.pathname);
    if (!page || target.origin !== this.env.location.origin) {
      return;
    }
    event.preventDefault();
    const method = String(form.getAttribute('method') || 'get').toLowerCase();
    if (page === WebShell.SIGNOUT_PATH) {
      this.signOut();
      return;
    }
    if (method !== 'post') {
      const fields = ConsoleRuntime.fieldsOf(this.formDataOf(form));
      if (page === WebShell.REALM_SWITCH_PATH) {
        this.switchRealm(String(fields.realm || ''), String(fields.to || ''));
        return;
      }
      const qs = new URLSearchParams(fields).toString();
      this.go(page + (qs ? '?' + qs : '') + target.hash);
      return;
    }
    this.submit(form, event.submitter || null);
  }

  // SIGNING OUT ends the tokens here and the sign-on session they came from:
  // the protocol-independent sign-out page ends the session, and with it the
  // tokens issued on it (`AdminApi`'s session check refuses them).
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

  // THE COPY BUTTONS, which `/admin/copy.js` revealed and served: drawn
  // hidden so that without script the page is the page it was, revealed
  // here, and a click writes the text to the clipboard.
  /**
   * Reveals and wires the copy buttons on the page drawn.
   *
   * @returns nothing
   */
  wireCopyButtons(): void {
    const buttons = this.env.document.querySelectorAll(
      'button.copybtn[data-copy]');
    const nav = this.env.navigator;
    for (let i = 0; i < buttons.length; i++) {
      const button = buttons[i];
      button.hidden = false;
      button.addEventListener('click', function () {
        if (nav && nav.clipboard) {
          nav.clipboard.writeText(button.getAttribute('data-copy') || '');
        }
      });
    }
  }

  /**
   * Starts the console: wires the document and draws the first page.
   *
   * @returns nothing
   */
  async start(): Promise<void> {
    const self = this;
    this.env.document.addEventListener('click', function (event) {
      self.onClick(event);
    });
    this.env.document.addEventListener('submit', function (event) {
      self.onSubmit(event);
    });
    if (this.env.window) {
      this.env.window.addEventListener('popstate', function () {
        self.prefix = ConsoleRuntime.prefixOf(self.env.location.pathname);
        self.route();
      });
    }
    await this.route();
  }
}

export = ConsoleRuntime;
