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
import WebAnswers = require('./web_answers');

type Json = any;

// The console's client: public, DPoP-bound (`sender_constraints.ts`,
// `DPOP_BOUND_PUBLIC_CLIENTS`).
const CLIENT_ID = 'sts-admin-console';
// What it asks for: an ID Token for who signed in, the two scopes the
// management API takes, narrowed at issuance to the roles the person holds,
// and the console's own (#454), which every person signing in here is
// issued through the ADMIN_CONSOLE role this client confers.
const SCOPE = 'openid admin:read admin:write admin:console';
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
  // The path and query of the page last drawn: a `popstate` that changes
  // neither is a fragment's, which the browser has already answered.
  private drawnAt: string;
  private spec: Json;

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
    this.drawnAt = '';
    this.spec = null;
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
    return this.send(method, this.url(path), body);
  }

  /**
   * Calls the management API at an absolute URL — `api()`'s work, and what
   * the explorer's `window.stsConsoleFetch` reaches.
   *
   * @param method - the method
   * @param target - the absolute URL
   * @param body - an object (sent as JSON), a JSON string, a FormData, or
   *   nothing
   * @returns the response, or null when a sign-in began
   */
  async send(method: string, target: string, body?: Json): Promise<Json> {
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.accessToken && now > this.expiresAt - REFRESH_EARLY * 1000) {
      await this.refresh();
    }
    if (!this.accessToken) {
      await this.beginSignIn(this.here());
      return null;
    }
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
        } else if (body.rawUpload) {
          // A FILE AS THE BODY, for an operation that takes bytes rather
          // than JSON (`multipartBody()`).
          headers['Content-Type'] = body.contentType;
          payload = body.rawUpload;
        } else if (typeof body === 'string') {
          headers['Content-Type'] = 'application/json';
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
      // THE OPERATIONS OF BOTH KINDS (#454): the index, `GET /admin-api`,
      // lists the management operations alone, and a form here may post to
      // one of the console's own form helpers.
      const index = await this.apiJson('GET', '/admin-api/console/operations');
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
  draw(title: string, active: string, inner: string, up: Json,
       banner?: string): void {
    const query = ConsoleRuntime.queryOf(this.env.location.search);
    const notice = String(query.notice || '').slice(0, 500);
    const error = String(query.error || '').slice(0, 500);
    // A PAGE DRAWN IN PLACE from an act's answer says what the act did
    // itself, and the location's notice belongs to an earlier one.
    const messages = banner !== undefined ? banner
      : kit.flash((notice ? '<div class="ok">' + kit.esc(notice) + '</div>'
                          : '') +
                  (error ? '<div class="err">' + kit.esc(error) + '</div>'
                         : ''));
    const shell = this.shell || { gate: null, sections: [], realm: { id: '',
      name: '' }, navLabels: {}, version: {}, persistence: {} };
    this.env.document.title = title + ' — IYA STS admin';
    this.env.document.body.innerHTML = ConsoleRuntime.realmLinks(
      WebShell.frame(shell, {
        title: title, active: active, up: up, inner: messages + inner,
        path: this.here() }), this.prefix);
    // EVERY DRAWING replaces the panels a tab's `:target` named — a page
    // routed to, a round trip, an act's answer — so the fragment is made
    // the target again (targetFragment()), and what was drawn is recorded
    // so the `popstate` that causes is known for a fragment's.
    this.drawnAt = this.env.location.pathname + this.env.location.search;
    this.targetFragment();
    this.wireCopyButtons();
    this.loadPageScripts();
  }

  // A SCRIPT A PAGE NAMES (`data-script`): markup drawn by `innerHTML` runs
  // none, so the explorer names its script and it is loaded here, from this
  // origin, after the page is in place — `script-src 'self'` is all it
  // needs.
  /**
   * Loads the scripts the page drawn names.
   *
   * @returns nothing
   */
  loadPageScripts(): void {
    const doc = this.env.document;
    const named = doc.querySelectorAll('[data-script]');
    for (let i = 0; i < named.length; i++) {
      const src = named[i].getAttribute('data-script');
      if (!src || !/^\/admin\//.test(src)) {
        continue;
      }
      const script = doc.createElement('script');
      script.src = this.prefix + src;
      doc.body.appendChild(script);
    }
  }

  // A PAGE UNDER A REALM'S PREFIX LINKS INTO THAT REALM. The renderers draw
  // root-relative addresses (`/admin/users`, a form's `action`, a button's
  // `formaction`), and the server-rendered console prefixed every one with
  // the realm's on the way out (`common/app.js` `withRealmLinks()`); the
  // static console draws them itself, so it does the same: `="/` and not
  // `="//`, which is another host.
  /**
   * Prefixes every root-relative `href`, `action`, `formaction` and `src`.
   *
   * @param html - the page
   * @param prefix - the realm's path prefix, or '' for the default realm
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

  // A TAB IS A FRAGMENT (`#tab-config`), and a panel is shown by CSS's
  // `:target` — which the browser sets during a fragment NAVIGATION and never
  // for an element drawn after it. So after a page is drawn whose address
  // carries a fragment (a deep link, a reload, a link to another page's
  // tab), the fragment is navigated to again — replacing the history entry
  // rather than adding one — so `:target` matches the element now in the
  // page. The `popstate` that follows changes neither path nor query, and is
  // left alone (`start()`).
  /**
   * Makes the address's fragment the `:target` of the page just drawn.
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
   * Draws the page in hand again, with what a just-finished act left.
   *
   * @param state - for the page's view: what the act answered, or null
   * @returns nothing
   */
  drawView(state: Json, banner?: string): void {
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
              page.path, WebPages.render(page.path, json, ctx), up, banner);
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

  // A JOINED FIELD (#219): ONE drop-down whose name is `a|b` and whose
  // values are `x|y` stands for two fields, `a=x` and `b=y`. It is how a
  // form offers only the PAIRS that go together — Monitoring → Risk's
  // dataset and its format — where two drop-downs would offer every
  // combination and leave the server to refuse most of them. The operation
  // is sent the two fields it has always taken; nothing in the API changes.
  // A value with fewer parts than the name leaves the rest empty, which the
  // operation refuses as it would an empty field.
  /**
   * Splits every joined field (`a|b` = `x|y`) of a form into its parts
   * (`a` = `x`, `b` = `y`), in place.
   *
   * @param data - the form's FormData
   */
  static splitJoinedFields(data: Json): void {
    const joined: Json[] = [];
    data.forEach(function (value, name) {
      if (String(name).indexOf('|') > 0 && typeof value === 'string') {
        joined.push({ name: String(name), value: value });
      }
    });
    const seen = {};
    joined.forEach(function (one) {
      if (!seen[one.name]) {
        seen[one.name] = true;
        data.delete(one.name);
      }
      const parts = String(one.value).split('|');
      one.name.split('|').forEach(function (part, i) {
        data.append(part, parts[i] === undefined ? '' : parts[i]);
      });
    });
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

  // WHAT AN OPERATION TAKES. A form carries fields only the server-rendered
  // console read — `back` and `from` (where to send the browser after),
  // `csrf_token` — and every field as a string, and the management API
  // refuses a member its schema does not name and checks each one's type.
  // So a form's fields are shaped by the operation's own request schema,
  // read from the OpenAPI document (fetched once): only the members it
  // declares, a lone value given where it takes a list, a checkbox's value
  // where it takes a boolean, a number where it takes only a number.
  /**
   * The request schema of a POST operation, from the OpenAPI document.
   *
   * @param operation - the operation's path, `/admin-api/groups/create`
   * @returns the schema with its `$ref` resolved, or null
   */
  async requestSchema(operation: string): Promise<Json> {
    if (!this.spec) {
      // BOTH DOCUMENTS, ONE TABLE OF PATHS (#454): a form posts to a
      // management operation or to one of the console's own form helpers,
      // and each is described by its own document. The components are the
      // same in both.
      const answer = await this.apiJson('GET', '/admin-api/openapi.json');
      const own = await this.apiJson('GET', '/admin-api/console/openapi.json');
      const management = answer && answer.status === 200 && answer.json
        ? answer.json : {};
      const consoleDoc = own && own.status === 200 && own.json ? own.json
                                                               : {};
      this.spec = Object.assign({}, management, {
        paths: Object.assign({}, consoleDoc.paths || {},
                             management.paths || {}) });
    }
    const op = ((this.spec.paths || {})[operation] || {}).post;
    const schema = op && op.requestBody && op.requestBody.content &&
      op.requestBody.content['application/json'] &&
      op.requestBody.content['application/json'].schema;
    return schema ? this.deref(schema) : null;
  }

  // A FORM THAT CARRIES A FILE (#446): the server-rendered console read its
  // multipart body in the page's own handler, and no operation takes
  // multipart. So it is sent as its operation takes it: an operation whose
  // only bodies are bytes (the risk dataset upload) is sent the FILE as the
  // body, typed by its name, with the form's other fields as query
  // parameters; a JSON operation is sent the fields, each file as
  // `{ name, text }` under its input's name (the RFC 9728 document).
  /**
   * The operation and body a multipart form is sent as.
   *
   * @param operation - the operation's path
   * @param data - the form's FormData, the submitter's value in it
   * @returns `{ operation, body }` for `api()`
   */
  async multipartBody(operation: string, data: Json): Promise<Json> {
    if (!this.spec) {
      await this.requestSchema(operation);
    }
    const op = ((this.spec.paths || {})[operation] || {}).post || {};
    const content = (op.requestBody && op.requestBody.content) || {};
    const fields: Json = {};
    const files: Json[] = [];
    data.forEach(function (value, name) {
      if (value && typeof value === 'object' && 'size' in value &&
          'name' in value) {
        if (value.size > 0) {
          files.push({ name: name, file: value });
        }
        return;
      }
      fields[name] = name in fields
        ? ([] as any[]).concat(fields[name], value) : value;
    });
    if (!content['application/json'] && Object.keys(content).length) {
      const types = Object.keys(content);
      const file = files.length ? files[0].file : null;
      const fileName = file ? String(file.name || '') : '';
      const type = /\.gz$/i.test(fileName) &&
                   types.indexOf('application/gzip') >= 0
        ? 'application/gzip'
        : (/\.zip$/i.test(fileName) && types.indexOf('application/zip') >= 0
          ? 'application/zip'
          : (types.indexOf('application/octet-stream') >= 0
            ? 'application/octet-stream' : types[0]));
      const query = new URLSearchParams();
      Object.keys(fields).forEach(function (name) {
        if (name === 'action') {
          return;
        }
        [].concat(fields[name]).forEach(function (value) {
          if (String(value) !== '') {
            query.append(name, String(value));
          }
        });
      });
      const qs = query.toString();
      return { operation: operation + (qs ? '?' + qs : ''),
               body: file ? { rawUpload: file, contentType: type } : '' };
    }
    for (let i = 0; i < files.length; i++) {
      fields[files[i].name] = { name: String(files[i].file.name || ''),
                                text: await files[i].file.text() };
    }
    return { operation: operation,
             body: this.shapeFields(fields,
                                    await this.requestSchema(operation)) };
  }

  /**
   * Resolves a `$ref` into the OpenAPI document's components.
   *
   * @param schema - a schema, or a `{ $ref }`
   * @returns the schema it names
   */
  deref(schema: Json): Json {
    let one = schema;
    for (let i = 0; i < 5 && one && one.$ref; i++) {
      const parts = String(one.$ref).replace(/^#\//, '').split('/');
      let at = this.spec;
      parts.forEach(function (part) {
        at = at ? at[part] : null;
      });
      one = at;
    }
    return one || null;
  }

  /**
   * Shapes a form's fields to an operation's request schema.
   *
   * @param fields - the form's fields
   * @param schema - the operation's request schema, or null for none
   * @returns the body to send
   */
  shapeFields(fields: Json, schema: Json): Json {
    const self = this;
    if (!schema || !schema.properties) {
      return fields;
    }
    const out = {};
    const has = function (name) {
      return Object.prototype.hasOwnProperty.call(schema.properties, name);
    };
    // A MEMBER A PATTERN NAMES (`patternProperties`): the field grid's
    // `field.<attribute>.<n>` boxes, which no list of properties could
    // name one by one.
    const patterned = function (name) {
      const patterns = schema.patternProperties || {};
      const key = Object.keys(patterns).filter(function (one) {
        return new RegExp(one).test(name);
      })[0];
      return key ? patterns[key] : null;
    };
    // A REPEATED CHECKBOX IS THE LIST MEMBER: a column of boxes named
    // `attribute` (or `claim`, or `protocol`) posts one value per ticked
    // box, and the operation takes them as `attributes`. Left out, an
    // operation that REPLACES a selection would be sent none and empty it.
    const fieldsIn = {};
    Object.keys(fields).forEach(function (name) {
      const plural = name + 's';
      if (!has(name) && has(plural) && !patterned(name)) {
        const prop = self.deref(schema.properties[plural]) || {};
        if ([].concat(prop.type || []).indexOf('array') >= 0) {
          fieldsIn[plural] = ([] as any[]).concat(fieldsIn[plural] || [],
                                                  fields[name]);
          return;
        }
      }
      fieldsIn[name] = name in fieldsIn
        ? ([] as any[]).concat(fieldsIn[name], fields[name])
        : fields[name];
    });
    Object.keys(fieldsIn).forEach(function (name) {
      const pattern = has(name) ? null : patterned(name);
      if (!has(name) && !pattern) {
        if (schema.additionalProperties !== false) {
          out[name] = fieldsIn[name];
        }
        return;
      }
      const prop = self.deref(pattern || schema.properties[name]) || {};
      const types = [].concat(prop.type || []);
      let value = fieldsIn[name];
      // AN EMPTY BOX IS AN ABSENT VALUE where the schema could not take an
      // empty string — a pattern, a minimum length, a type that is not a
      // string — as the server-rendered console's form parser read it. It
      // is kept where a string is all the schema asks, so a field can still
      // be cleared.
      if (value === '' && (prop.pattern || prop.minLength > 0 ||
                           (types.length && types.indexOf('string') < 0))) {
        return;
      }
      // JSON IN A TEXT AREA where the schema takes an object, or a list of
      // objects: what the form calls a document is a value.
      const items = prop.items ? self.deref(prop.items) || {} : {};
      const wantsObject = types.indexOf('object') >= 0 &&
                          types.indexOf('string') < 0;
      const wantsObjects = types.indexOf('array') >= 0 &&
                           [].concat(items.type || []).indexOf('object') >= 0;
      if (typeof value === 'string' && (wantsObject || wantsObjects)) {
        try {
          const parsed = JSON.parse(value);
          if (parsed && typeof parsed === 'object') {
            value = parsed;
          }
        } catch (e) {
          // Not JSON: sent as typed, and the operation names what it is.
          value = fieldsIn[name];
        }
      }
      if (types.indexOf('array') >= 0 && types.indexOf('string') < 0 &&
          !Array.isArray(value)) {
        value = value === '' ? [] : [value];
      } else if (Array.isArray(value) && types.length &&
                 types.indexOf('array') < 0) {
        value = value[value.length - 1];
      }
      if (typeof value === 'string' && types.length &&
          types.indexOf('string') < 0) {
        if (types.indexOf('boolean') >= 0 &&
            /^(true|false|on|off|1|0|yes|no)$/i.test(value)) {
          value = /^(true|on|1|yes)$/i.test(value);
        } else if ((types.indexOf('integer') >= 0 ||
                    types.indexOf('number') >= 0) && value !== '' &&
                   isFinite(Number(value))) {
          value = Number(value);
        }
      }
      out[name] = value;
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
    // A BUTTON MAY POST ELSEWHERE (`formaction`), and a section's Reset
    // does: its own address names the setting in its query, which is
    // carried into the fields the operation is sent.
    const posted = (submitter && submitter.getAttribute &&
                    submitter.getAttribute('formaction')) ||
                   form.getAttribute('action') || this.here();
    const target = new URL(posted, this.env.location.href);
    const page = this.consolePath(target.pathname);
    const data = this.formDataOf(form);
    // THE PRESSED BUTTON'S VALUE WINS over a field of the same name: a
    // create form's Generate secret is `action=generate-secret` beside the
    // form's hidden `action=create`, and the server-rendered console read
    // the last of the two. Taking the first would create the application.
    if (submitter && submitter.name) {
      data.delete(submitter.name);
      data.append(submitter.name, submitter.value);
    }
    // A `formaction`'s query TAKES THE PLACE of the form's field of the same
    // name — the PKI workbench's Generate names `action=generate-keys` over
    // the form's hidden `issue-certificate` — rather than joining it.
    const named = {};
    target.searchParams.forEach(function (value, name) {
      if (!named[name]) {
        named[name] = true;
        data.delete(name);
      }
      data.append(name, value);
    });
    // A FIELD THAT CARRIES TWO (#219): `dataset|format` is sent as the
    // operation takes it, `dataset` and `format`.
    ConsoleRuntime.splitJoinedFields(data);
    const fields = ConsoleRuntime.fieldsOf(data);
    const action = Array.isArray(fields.action) ? fields.action[0]
                                                : String(fields.action || '');
    // A ROUND TRIP WRITES NOTHING: "+", a bin, a view switch. Drawn again
    // here from what the form holds, and never sent — each of those forms'
    // hidden `action` is the write (`web_answers.ts`).
    if (page && this.view && WebAnswers.isRoundTrip(page, fields)) {
      this.view.json = WebAnswers.roundTrip(page, fields, this.view.json);
      this.drawView(null, '');
      return;
    }
    // FILL asks for the invented person and writes nothing either.
    if (page === '/admin/users/new' && this.view &&
        fields.fill !== undefined) {
      const invent = await this.apiJson('GET', '/admin-api/users/new?' +
        new URLSearchParams({ invent: String(fields.username || '') })
          .toString());
      if (!invent) {
        return;
      }
      const drawn = WebAnswers.filled(fields, invent.json, this.view.json);
      this.view.json = drawn.json;
      this.drawView(null, drawn.banner);
      return;
    }
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
    const sent = multipart
      ? await this.multipartBody(operation, data)
      : { operation: operation,
          body: this.shapeFields(fields, await this.requestSchema(operation)) };
    const res = await this.api('POST', sent.operation, sent.body);
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
    // FILES IN THE ANSWER (the key exports): what the server-rendered
    // console answered with an attachment, the operation answers as named
    // base64, and each is saved as the attachment was.
    if (json && json.ok && Array.isArray(json.files) && json.files.length &&
        json.files.every(function (one) {
          return one && typeof one.base64 === 'string' && one.name;
        })) {
      for (let i = 0; i < json.files.length; i++) {
        this.saveBase64(String(json.files[i].name),
                        String(json.files[i].mime ||
                               'application/octet-stream'),
                        json.files[i].base64);
      }
      return;
    }
    if (json && json.ok && action === 'reveal-secret' && this.view) {
      this.drawView({ revealed: { secret: fields.secret,
                                  value: json.value } });
      return;
    }
    // A REALM MADE OR REMOVED changes the shell's realm switcher, so the
    // shell is asked again on the next draw.
    if (json && json.ok && page === '/admin/realms') {
      this.shell = null;
    }
    // A SECRET SHOWN ONCE is drawn in place — never on a URL, never in the
    // history — and is gone when the reader moves on.
    // Its way back is to the tab the form was on, as an act's return is.
    const once = WebAnswers.once(page, action, fields, json, {
      back: back + String(this.env.location.hash || ''),
      base: this.env.location.origin + this.prefix,
      realmRoot: (this.shell && this.shell.realmRoot) ||
                 this.env.location.origin });
    if (once) {
      this.view = null;
      this.draw(once.title, once.active, once.html, null, '');
      return;
    }
    // A REDRAW FROM THE ANSWER: a refused create or edit with every box as
    // it was, a generated secret or a loaded document in its form, the
    // workbench's next draft, a resolution under the form that asked.
    const again = this.view
      ? WebAnswers.redraw(page, action, fields, json, this.view.json) : null;
    if (again) {
      this.view.json = again.json;
      this.drawView(null, again.banner);
      return;
    }
    // AN ACT THAT LANDS ELSEWHERE — a new application on its entry, a
    // group acted on on that group (`WebAnswers.landing()`) — with its
    // notice there.
    // WHAT AN ANSWER SAYS: `message`, or — where a handler describes a
    // success in `why`, as the PKI page's upload does — that, as the
    // server-rendered console's strip read it.
    const said = String((json && (json.message || json.why)) || 'Done.');
    const landing = page ? WebAnswers.landing(page, action, json, back)
                         : null;
    if (landing) {
      await this.go(landing + (landing.indexOf('?') < 0 ? '?' : '&') +
                    'notice=' + encodeURIComponent(said));
      return;
    }
    const key = json && json.ok ? 'notice' : 'error';
    const message = json && json.ok
      ? said
      : ((json && json.errors) || []).join(' ') ||
        String((json && (json.why || json.error_description ||
                         json.error)) || 'Refused.');
    // BACK TO THE TAB THE FORM WAS ON: the notice goes in the query and the
    // fragment stays, so the answer is shown where the control was.
    await this.go(back + (back.indexOf('?') < 0 ? '?' : '&') + key + '=' +
                  encodeURIComponent(message) +
                  String(this.env.location.hash || ''));
  }

  /**
   * Saves a response the server said is a file.
   *
   * @param res - the response
   * @param disposition - its Content-Disposition
   * @returns nothing
   */
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
    if (!el) {
      return;
    }
    const url = new URL(el.getAttribute('href') || '', this.env.location.href);
    if (url.origin !== this.env.location.origin) {
      return;
    }
    // A RESOURCE OF THE API — a certificate, a page's document — needs this
    // console's token, which a navigation cannot carry: it is fetched with
    // the token and a proof, and saved.
    const apiPath = url.pathname.indexOf(this.prefix + '/admin-api') === 0
      ? url.pathname.slice(this.prefix.length) : null;
    const page = this.consolePath(url.pathname);
    const format = url.searchParams.get('format');
    if (apiPath || (page && format)) {
      event.preventDefault();
      this.fetchAndSave(apiPath ? apiPath + url.search
                                : this.documentOf(page, url, format),
                        el.getAttribute('download') || '');
      return;
    }
    if (el.target === '_blank' || el.hasAttribute('download') || !page) {
      return;
    }
    event.preventDefault();
    if (url.pathname === this.env.location.pathname &&
        url.search === this.env.location.search && url.hash) {
      this.env.location.hash = url.hash;
      return;
    }
    // The fragment goes with the address, and targetFragment() makes it
    // the drawn page's `:target` (another page's tab, a section to land on).
    this.go(page + url.search + url.hash);
  }

  // A PAGE'S OTHER FORMS — `?format=json`, `?format=svg` — were the
  // server-rendered page answered in another shape. The same is the page's
  // operation asked with that format: the answer as JSON, or the drawing.
  /**
   * The operation path a page's `?format=` link names.
   *
   * @param page - the console path
   * @param url - the link
   * @param format - `json` or `svg`
   * @returns the operation's path and query
   */
  documentOf(page: string, url: Json, format: string): string {
    const row = WebPages.PAGES.filter(function (one) {
      return one.path === page;
    })[0];
    if (!row) {
      return '/admin-api';
    }
    const query = ConsoleRuntime.queryOf(url.search);
    delete query.format;
    const mapped = WebPages.operationQuery(row.path, query);
    if (format === 'svg') {
      mapped.format = 'svg';
    }
    const qs = new URLSearchParams(mapped).toString();
    return row.operation + (qs ? '?' + qs : '');
  }

  /**
   * Fetches an API resource with this console's token and saves it.
   *
   * @param path - the path and query under the realm, `/admin-api/...`
   * @param name - the file name a `download` attribute gave, or ''
   * @returns nothing
   */
  async fetchAndSave(path: string, name: string): Promise<void> {
    const res = await this.api('GET', path);
    if (!res) {
      return;
    }
    const disposition = String((res.headers && res.headers.get &&
                                res.headers.get('Content-Disposition')) || '');
    const type = String((res.headers && res.headers.get &&
                         res.headers.get('Content-Type')) || '');
    const fallback = name ||
      (path.split('?')[0].split('/').pop() || 'download') +
      (/svg/.test(type) ? '.svg' : (/json/.test(type) ? '.json' : ''));
    await this.save(res, disposition ||
                    'attachment; filename="' + fallback + '"');
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
    // THE REALM SWITCHER POSTS AT THE SERVICE'S ROOT, whatever realm the
    // page is in — it moves between realms — so it is claimed by its path
    // alone, before the realm's own prefix is asked.
    const page = target.pathname === WebShell.REALM_SWITCH_PATH
      ? WebShell.REALM_SWITCH_PATH : this.consolePath(target.pathname);
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
    const doc = this.env.document;
    const buttons = doc.querySelectorAll('button.copybtn[data-copy]');
    const nav = this.env.navigator;
    // OUTSIDE A SECURE CONTEXT `navigator.clipboard` is undefined — a console
    // reached over plain http — so a selected, hidden text area and
    // `execCommand('copy')` stand in, as the parent project's `copyField()`
    // and the deleted `/admin/copy.js` did.
    const fallback = function (text: string): boolean {
      const area = doc.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      doc.body.appendChild(area);
      area.focus();
      area.select();
      let ok = false;
      try {
        ok = doc.execCommand('copy');
      } catch (e) {
        // A browser that has dropped execCommand: the button says it failed.
        ok = false;
      }
      doc.body.removeChild(area);
      return ok;
    };
    const copied = function (button: Json, ok: boolean): void {
      const label = button.textContent;
      button.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(function () {
        button.textContent = label;
      }, 1500);
    };
    for (let i = 0; i < buttons.length; i++) {
      const button = buttons[i];
      button.hidden = false;
      button.addEventListener('click', function () {
        const text = button.getAttribute('data-copy') || '';
        if (nav && nav.clipboard && nav.clipboard.writeText) {
          nav.clipboard.writeText(text).then(function () {
            copied(button, true);
          }, function () {
            copied(button, fallback(text));
          });
          return;
        }
        copied(button, fallback(text));
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
      // THE EXPLORER'S WAY TO CALL (`admin_api_explorer.js`): this
      // runtime's token and a proof by its key, for a path on this origin.
      this.env.window.stsConsoleFetch = function (method, path, body) {
        return self.send(String(method || 'GET'),
                         self.env.location.origin + String(path), body);
      };
      this.env.window.addEventListener('popstate', function () {
        // A FRAGMENT'S OWN NAVIGATION — a tab pressed, or targetFragment() —
        // changes neither the path nor the query, and the browser has
        // already shown its target. Drawing the page again would draw the
        // panel after the navigation and lose `:target`: the tab would flash
        // and fall back to the first.
        if (self.env.location.pathname + self.env.location.search ===
            self.drawnAt) {
          return;
        }
        self.prefix = ConsoleRuntime.prefixOf(self.env.location.pathname);
        self.route();
      });
    }
    await this.route();
  }
}

export = ConsoleRuntime;
