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
// its OAuth half shared (`common/web_spa_client.ts`): it signs in as the
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
// ONE ACCOUNT PER TAB (#561, with `authn.multipleAccounts` on), on the
// console's pattern: the tab's account in sessionStorage sent as
// `login_hint` on every sign-in; the account menu's Switch, Sign in with
// another account and Sign out…; a switch that asks first over unsaved
// changes, aborts what is in flight, discards every view and token this tab
// holds and refuses an answer for another subject; and `?accounts=another`,
// which a public page's *Sign in with another account* links here with, as
// this portal's own authorization request with `prompt=login`. With the
// setting off none of it is drawn or sent.
//
// A `web_` MODULE: it requires other `web_` modules only and logs nothing.
// Everything it touches in the browser arrives through the constructor.
// ---------------------------------------------------------------------------

import SpaClient = require('../common/web_spa_client');
import WebMessages = require('../common/web_messages');
import kit = require('./web_portal_kit');
import PortalShell = require('./web_portal_shell');
import PortalPages = require('./web_portal_pages');
import PortalWebAuthn = require('./web_portal_webauthn');
import WebAccounts = require('../common/web_accounts');

type Json = any;

// The portal's client: public, DPoP-bound (`sender_constraints.js`).
const CLIENT_ID = 'sts-user-portal';
// An ID Token for who signed in, the one scope the account API takes, and an
// owner's two on the management API (#607) — issued only to a person who
// owns something, so a token without them is the ordinary case.
const SCOPE = 'openid account:manage owner:read owner:write';
// The key the sign-in's one-use values cross the redirect under.
const SIGNIN_KEY = 'sts-portal-signin';
// How long before an access token's expiry it is refreshed, in seconds.
const REFRESH_EARLY = 30;
// The account API's base.
const API = '/account-api';
// THE MANAGEMENT API'S (#607): what a person administers what they own
// through, with a token of its own — the same grant, refreshed with this as
// its `resource` (RFC 8707), so one sign-in serves both.
const ADMIN_API = '/admin-api';
// What `sendOnce()` answers when the request needs a sign-in first.
const NEEDS_SIGN_IN = { needsSignIn: true };
// What it answers for a request the tab's account changed under (#561):
// aborted, or answered after the switch — either way not believed.
const ABORTED = { aborted: true };
// Where the tab's account is kept (#561), beside the sign-in's record.
const ACCOUNT_KEY = 'sts-portal-account';
// What a sign-in's extra parameters carry that is this runtime's and not
// the authorization request's.
const OWN_EXTRAS = ['expect', 'another', 'login_hint'];

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
  // THE OWNER TOKEN (#607): an access token for `/admin-api`, when it runs
  // out, and the scopes it was issued — owner:read and owner:write only for
  // a person who owns something.
  private ownerToken: string;
  private ownerExpiresAt: number;
  private ownerScopes: string[];
  // WHETHER A FORM ON THE PAGE DRAWN HAS BEEN TYPED IN (#561): a switch asks
  // first while one has.
  private dirty: boolean;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects (`SpaClient`'s), and for a test
   *   `formDataOf`
   */
  constructor(env: Json) {
    super(env, PortalRuntime.prefixOf(env.location.pathname), {
      clientId: CLIENT_ID, scope: SCOPE,
      elsewhere: { '/oauth2': 'data-sts-oauth', '/admin-api': 'data-sts-api',
                   '/logout': 'data-sts-authn' },
      accountKey: ACCOUNT_KEY
    });
    this.dirty = false;
    this.ownerToken = '';
    this.ownerExpiresAt = 0;
    this.ownerScopes = [];
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
    return PortalRuntime.prefixAt(pathname, '/portal');
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

  /**
   * The management API, the second resource the portal's sign-in names
   * (#607).
   *
   * @returns the resource indicator
   */
  ownerResource(): string {
    return this.url(ADMIN_API);
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
      // BOTH RESOURCES (#607, RFC 8707): the account API's token is redeemed
      // from the code, and the management API's is refreshed from the same
      // grant when an owner's page asks for it.
      code_challenge_method: 'S256',
      resource: [this.resource(), this.ownerResource()],
      // OpenID Connect's nonce, which FAPI 1.0 requires (`SpaClient`).
      nonce: await this.nonceFor(verifier)
    };
    Object.keys(extra || {}).forEach(function (name) {
      if (extra[name] && OWN_EXTRAS.indexOf(name) < 0) {
        params[name] = String(extra[name]);
      }
    });
    // THE TAB'S ACCOUNT (#561), on every sign-in — a step-up's and a
    // reload's among them — so the authorization server answers for this
    // tab's session and no other; none where the tab keeps none, which is
    // every tab with the setting off.
    const hint = this.hintFor(extra);
    if (hint) {
      params.login_hint = hint;
    }
    // Pushed first where the realm requires it (RFC 9126, `SpaClient`).
    return this.authorizationRequestUrl(params);
  }

  /**
   * Sends the browser to sign in, remembering where to come back to.
   *
   * @param returnTo - the path and query to land on after
   * @param extra - `prompt` and `acr_values` for a step-up; for a switch
   *   (#561) `login_hint` ('' for none), `expect` (the subject the answer
   *   must be for) and `another`; or nothing
   * @returns nothing
   */
  async beginSignIn(returnTo: string, extra?: Json): Promise<void> {
    const verifier = this.random(32);
    const state = this.random(16);
    const asked = extra || {};
    // `expect` and `another` are written only where a switch set them, so
    // the record of an ordinary sign-in is the one it always was.
    const record: Json = { verifier: verifier, state: state,
                           returnTo: returnTo, prefix: this.prefix };
    if (asked.expect) {
      record.expect = String(asked.expect);
    }
    if (asked.another) {
      record.another = true;
    }
    this.env.sessionStorage.setItem(SIGNIN_KEY, JSON.stringify(record));
    this.env.location.assign(await this.authorizeUrl(state, verifier, extra));
  }

  /**
   * Finishes a sign-in on the callback.
   *
   * @returns nothing
   */
  async finishSignIn(): Promise<void> {
    // A JARM answer is opened and checked first (`SpaClient`).
    const query = await this.openAuthorizationResponse(
      SpaClient.queryOf(this.env.location.search));
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
      // THE RETURN TAB of a same-device wallet holds no PKCE record. The
      // tab that opened the portal still does, and it redeems the code.
      if (query.code && query.state &&
          await this.handCallbackToStarter(query)) {
        this.env.history.replaceState(null, '',
          this.prefix + kit.BASE + '/callback');
        this.drawProblem('Continue in your other tab',
          'This sign-in is finishing in the tab where you opened the ' +
          'portal. You can close this one.');
        return;
      }
      // THE SESSION IS ALREADY THERE. The wallet and the passkey finished
      // in this tab, so the authorization server holds a session. This tab
      // has no matching PKCE record, and no waiting tab took the callback.
      // The Sign in link under the old refusal started a fresh request,
      // which that session accepts. Start it, rather than call a finished
      // sign-in an error.
      this.env.history.replaceState(null, '', this.prefix + kit.BASE);
      await this.beginSignIn(kit.BASE);
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
    if (!await this.nonceMatches(answer.json.id_token, saved.verifier)) {
      this.drawProblem('Signing in failed',
        'The ID Token does not carry the nonce this sign-in sent. Open the ' +
        'portal again to sign in.');
      return;
    }
    // A SWITCH IS FOR ONE ACCOUNT (#561), the console's check: an answer for
    // another subject is refused and its tokens are not kept, so the tab
    // stays the account it was — a reload resumes that one, by its hint.
    if (saved.expect &&
        !PortalRuntime.answerIsFor(String(saved.expect),
                                   answer.json.id_token)) {
      this.drawProblem('Switching accounts was refused',
        'The sign-in came back as another account than the one chosen, so ' +
        'this tab did not take it. Open the portal again to carry on as the ' +
        'account it was.');
      return;
    }
    const before = this.storedAccount();
    this.keepTokens(answer.json);
    this.me = null;
    this.env.history.replaceState(null, '',
      this.prefix + String(saved.returnTo || kit.BASE));
    await this.route();
    // AN ACCOUNT THIS TAB ADDED TO THE BROWSER is announced, so the other
    // tabs' menus are read again (#561); a reload as the same account is
    // not a change.
    if (saved.another || (before && before.sub !== this.subject)) {
      this.announceAccounts('added');
    }
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

  // ---------------------------------------------------------------------------
  // THE OWNER TOKEN (#607): the management API's access token, refreshed from
  // the one grant with `/admin-api` as its resource. The refresh token it
  // answers replaces the one in hand — rotation is one chain, whichever
  // resource a refresh names — and the account API's token is untouched.
  // ---------------------------------------------------------------------------
  /**
   * The owner token, refreshed when it is missing or running out.
   *
   * @returns `{ token, signIn }`: the token ('' where none is to be had), and
   *   whether the grant itself is gone, so signing in again is the way
   */
  async ownerAccess(): Promise<Json> {
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.ownerToken && now < this.ownerExpiresAt - REFRESH_EARLY * 1000) {
      return { token: this.ownerToken, signIn: false };
    }
    if (!this.refreshToken) {
      return { token: '', signIn: true };
    }
    const answer = await this.tokenRequest({
      grant_type: 'refresh_token', refresh_token: this.refreshToken,
      client_id: CLIENT_ID, resource: this.ownerResource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      this.ownerToken = '';
      this.ownerScopes = [];
      // A REFUSED REFRESH spent nothing, unless the grant is gone — an
      // `invalid_grant` — and then the account API's refresh will fail too.
      return { token: '', signIn: answer.json.error === 'invalid_grant' };
    }
    if (answer.json.refresh_token) {
      this.refreshToken = String(answer.json.refresh_token);
    }
    this.ownerToken = String(answer.json.access_token);
    this.ownerExpiresAt = now + (Number(answer.json.expires_in) || 300) * 1000;
    this.ownerScopes = String(answer.json.scope || '').split(/\s+/)
      .filter(Boolean);
    return { token: this.ownerToken, signIn: false };
  }

  /**
   * Calls the management API with the owner token (#607) and reads its JSON.
   * A token the authorization server would not issue — the person owns
   * nothing now — answers 403 with the reason, drawn on the page; a grant
   * that is gone sends the window to sign in again.
   *
   * @param method - GET or POST
   * @param path - `/admin-api/...` with its query
   * @param body - for a POST, an object
   * @returns `{ status, json }`, or null when a sign-in began
   */
  async ownerJson(method: string, path: string, body?: Json): Promise<Json> {
    const target = this.url(path);
    // THE IDENTITY IT IS SENT FOR (#561): a switch aborts it, and whatever
    // comes back after one is null, as a sign-in that began is.
    const identity = this.identity;
    for (let attempt = 0; attempt < 3; attempt++) {
      const access = await this.ownerAccess();
      if (identity !== this.identity) {
        return null;
      }
      if (!access.token) {
        if (access.signIn) {
          await this.beginSignIn(this.here());
          return null;
        }
        return { status: 403, json: { ok: false, errors: [
          this.t.text('portalOwned.edit.noToken')] } };
      }
      const headers: Json = {
        'Authorization': 'DPoP ' + access.token,
        'DPoP': await this.proof(method, target, access.token),
        'Accept': 'application/json',
        'Accept-Language': this.t.lang
      };
      if (body !== undefined && body !== null) {
        headers['Content-Type'] = 'application/json';
      }
      let res: Json = null;
      try {
        res = await this.env.fetch(target, { method: method,
          headers: headers,
          body: body !== undefined && body !== null ? JSON.stringify(body)
                                                    : undefined,
          signal: this.identitySignal() });
      } catch (e) {
        if (identity !== this.identity) {
          return null;
        }
        throw e;
      }
      if (identity !== this.identity) {
        return null;
      }
      this.keepNonce(res);
      if (res.status === 401) {
        const challenge = String((res.headers && res.headers.get &&
                                  res.headers.get('WWW-Authenticate')) || '');
        if (/use_dpop_nonce/.test(challenge) && attempt === 0) {
          continue;
        }
        // A token that stopped being one: drop it, and refresh once.
        this.ownerToken = '';
        if (attempt < 2) {
          continue;
        }
      }
      const json = await res.json().catch(function () {
        return null;
      });
      if (identity !== this.identity) {
        return null;
      }
      return { status: res.status, json: json };
    }
    return { status: 401, json: { ok: false, errors: [
      this.t.text('portalOwned.edit.noToken')] } };
  }

  /**
   * Tells whether the owner token carries a scope.
   *
   * @param scope - `owner:read` or `owner:write`
   * @returns whether it does
   */
  ownerMay(scope: string): boolean {
    return this.ownerScopes.indexOf(scope) >= 0;
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
    // THE IDENTITY IT IS SENT FOR (#561): a switch aborts it, and whatever
    // comes back after one is ABORTED, never drawn.
    const identity = this.identity;
    const now = this.env.now ? this.env.now() : Date.now();
    if (this.accessToken && now > this.expiresAt - REFRESH_EARLY * 1000) {
      await this.refresh();
    }
    if (identity !== this.identity) {
      return ABORTED;
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
      let res: Json = null;
      try {
        res = await this.env.fetch(target, { method: method,
          headers: headers,
          body: body !== undefined && body !== null ? JSON.stringify(body)
                                                    : undefined,
          signal: this.identitySignal() });
      } catch (e) {
        if (identity !== this.identity) {
          return ABORTED;
        }
        throw e;
      }
      if (identity !== this.identity) {
        return ABORTED;
      }
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
    const identity = this.identity;
    const res = await this.sendOnce(method, this.url(path), body);
    if (res === ABORTED) {
      return null;
    }
    if (res === NEEDS_SIGN_IN) {
      await this.beginSignIn(this.here() + String(this.env.location.hash ||
                                                  ''));
      return null;
    }
    const json = await res.json().catch(function () {
      return null;
    });
    if (identity !== this.identity) {
      return null;
    }
    return { status: res.status, json: json, res: res };
  }

  // An operation that takes no token is `publicJson()`, `WebPage`'s (#570).

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

  // A PAGE UNDER A REALM'S PREFIX LINKS INTO THAT REALM:
  // `PortalRuntime.realmLinks()` is `WebPage`'s (#570), inherited.

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
    // A page just drawn holds nothing typed (#561's unsaved-changes test).
    this.dirty = false;
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

  // A TAB OR A SECTION IS A FRAGMENT: `targetFragment()` is `WebPage`'s
  // (#570), inherited.

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
        cards: body, prefix: this.prefix, t: this.t,
        accounts: this.accounts, subject: this.subject }));
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
    // SIGN IN WITH ANOTHER ACCOUNT, ASKED FROM ANOTHER PAGE (#561): a public
    // page's control links here with `accounts=another`, and the portal's
    // own authorization request asks with `prompt=login`. The marker leaves
    // the address either way; with the setting off it is dropped and the
    // page is today's.
    if (!forNobody && query[WebAccounts.ANOTHER_PARAM] ===
        WebAccounts.ANOTHER_VALUE) {
      delete query[WebAccounts.ANOTHER_PARAM];
      const back = path + kit.queryOf(query) +
        String(this.env.location.hash || '');
      this.env.history.replaceState(null, '', this.prefix + back);
      const list = await WebAccounts.fetchList(this.env, this.prefix);
      if (list.enabled) {
        this.accounts = list;
        await this.signInAnother(back);
        return;
      }
    }
    // THE IDENTITY THIS PAGE IS DRAWN FOR (#561): a switch while it is
    // being fetched leaves it undrawn.
    const identity = this.identity;
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
      // THE BROWSER'S ACCOUNTS (#561), for the account menu, and the tab's
      // own kept from them; off, nothing is kept and the frame is today's.
      await this.readAccounts(String((this.me.user || {}).username || ''));
      const self = this;
      this.listenForAccounts(function () {
        self.redrawAccountMenu();
      });
      if (identity !== this.identity) {
        return;
      }
    }
    if (!page) {
      this.view = null;
      this.put('Not a page', PortalShell.bare('<div class="card"><p>' +
        '<code>' + kit.esc(path) + '</code> is not a page of this portal.' +
        '</p><p><a href="' + kit.BASE + '">' + kit.BASE + '</a></p></div>',
        this.me && this.me.version));
      return;
    }
    // A PAGE DRAWN FROM THE MANAGEMENT API (#607): one object a person
    // owns, read with the owner token.
    const adminPath = page.admin ? page.admin(query) : null;
    if (adminPath) {
      const loaded = await this.ownerJson('GET', adminPath);
      if (!loaded) {
        return;
      }
      this.view = { page: page, query: query, json: { owned: {
        status: loaded.status, answer: loaded.json || {},
        canWrite: this.ownerMay('owner:write'), query: query } } };
      this.drawView();
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

  // A form's fields as an object is `formFields()`, `WebPage`'s (#570).

  /**
   * Sends a POST form to the operation that mirrors it, and draws what it
   * answered.
   *
   * @param form - the form
   * @param submitter - the button pressed, if any
   * @returns nothing
   */
  async submit(form: Json, submitter: Json): Promise<void> {
    // A FORM ON AN OWNER'S PAGE (#607) goes to the management API operation
    // it names, with the owner token, and the page is drawn again with what
    // it answered.
    const adminOp = form.getAttribute && form.getAttribute('data-admin');
    if (adminOp) {
      await this.submitOwned(String(adminOp), this.formFields(form,
                                                              submitter));
      return;
    }
    const posted = (submitter && submitter.getAttribute &&
                    submitter.getAttribute('formaction')) ||
                   form.getAttribute('action') || this.here();
    const target = new URL(posted, this.env.location.href);
    const path = this.portalPath(target.pathname);
    const fields = this.formFields(form, submitter);
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

  /**
   * Sends an owner's form to the management API (#607) and draws the page
   * again, with the answer's message — and a secret it answered once, said
   * once — or its errors.
   *
   * @param path - `/admin-api/<kind>/<action>`
   * @param fields - the form's fields
   * @returns nothing
   */
  async submitOwned(path: string, fields: Json): Promise<void> {
    // A field named `fields.<attribute>` is one of an update's attributes,
    // and `lines.<attribute>` one whose values are a box's lines.
    const body: Json = {};
    Object.keys(fields).forEach(function (name: string) {
      const value = fields[name];
      const each = /^(fields|lines)\.(.+)$/.exec(name);
      if (!each) {
        body[name] = value;
        return;
      }
      body.fields = body.fields || {};
      body.fields[each[2]] = each[1] === 'lines'
        ? String(value || '').split(/\r?\n/).map(function (line: string) {
          return line.trim();
        }).filter(Boolean)
        : value;
    });
    const answer = await this.ownerJson('POST', path, body);
    if (!answer) {
      return;
    }
    const json = answer.json || {};
    const secret = json.clientSecret || json.client_secret ||
                   (json.secret && json.secret.value) || '';
    this.flash = json.ok === false || answer.status >= 400
      ? { error: (json.errors || []).join(' ') ||
                 this.t.text('portalOwned.edit.refused',
                             { status: answer.status }) }
      : { message: String(json.message ||
                          this.t.text('portalOwned.edit.saved')) +
                   (secret ? ' ' + this.t.text('portalOwned.edit.secretOnce',
                                               { secret: String(secret) })
                           : '') };
    await this.route();
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

  // `saveBase64()` is `WebPage`'s (#570), inherited.

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
    // THE ACCOUNT MENU'S CONTROLS (#561), drawn only with several accounts
    // on.
    const asked = this.accounts.enabled
      ? WebAccounts.actionOf(event.target) : null;
    if (asked && (asked.action === 'switch' || asked.action === 'another')) {
      event.preventDefault();
      if (asked.action === 'switch') {
        this.switchAccount(asked.key);
      } else {
        this.signInAnother();
      }
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
      const fields = this.formFields(form, null);
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
    // WHICH ACCOUNT (#561): with several in the browser, the sign-out is
    // told the tab's, which it preselects; with the setting off the address
    // is the one it always was.
    const kept = this.accounts.enabled ? this.storedAccount() : null;
    this.accessToken = '';
    this.refreshToken = '';
    this.ownerToken = '';
    this.env.location.assign(this.url('/logout') +
      (kept && kept.username
        ? '?login_hint=' + encodeURIComponent(kept.username) : ''));
  }

  // ---------------------------------------------------------------------------
  // SWITCHING ACCOUNTS IN THIS TAB (#561), the console's arrangement
  // (`admin-ui/web_runtime.ts`, *Switching accounts in this tab*): ask first
  // over a form typed in, abort what is in flight (`endIdentity()`), discard
  // every view and token (`discardViews()`), and sign in naming the account
  // and the subject the answer must be for. `/account-api` and the owner's
  // `/admin-api` still decide from the token's own subject; nothing here is
  // a boundary.
  // ---------------------------------------------------------------------------
  /**
   * Asks before leaving a page whose forms were typed in.
   *
   * @returns whether to go on
   */
  confirmLeave(): boolean {
    const win = this.env.window;
    if (!this.dirty || !win || typeof win.confirm !== 'function') {
      return true;
    }
    return !!win.confirm(this.t.has('portal.accounts.unsaved')
      ? this.t.text('portal.accounts.unsaved')
      : 'This page has changes that have not been saved. Switch account ' +
        'anyway? They will be lost.');
  }

  /**
   * Discards every view and token this tab holds for the account it was.
   *
   * @returns nothing
   */
  discardViews(): void {
    this.me = null;
    this.nobody = null;
    this.formTable = null;
    this.view = null;
    this.flash = null;
    this.ownerToken = '';
    this.ownerExpiresAt = 0;
    this.ownerScopes = [];
    this.discardClient();
  }

  /**
   * Switches this tab to another signed-in account of the browser.
   *
   * @param key - the account's key, from the menu
   * @returns nothing
   */
  async switchAccount(key: string): Promise<void> {
    const account = WebAccounts.byKey(this.accounts, key);
    if (!account) {
      this.redrawAccountMenu();
      return;
    }
    if (!this.confirmLeave()) {
      return;
    }
    const back = this.here() + String(this.env.location.hash || '');
    this.endIdentity();
    this.discardViews();
    await this.beginSignIn(back, {
      login_hint: String(account.username || account.sub || ''),
      expect: String(account.sub || '') });
  }

  /**
   * Signs this tab in as another account: a fresh sign-in (`prompt=login`)
   * with no hint, whose account the tab then is.
   *
   * @param returnTo - where to land after; this page where left out
   * @returns nothing
   */
  async signInAnother(returnTo?: string): Promise<void> {
    if (!this.confirmLeave()) {
      return;
    }
    const back = returnTo || this.here() + String(this.env.location.hash ||
                                                  '');
    this.endIdentity();
    this.discardViews();
    await this.beginSignIn(back, { login_hint: '', prompt: 'login',
                                   another: true });
  }

  /**
   * Draws the account menu's items again from the list in hand, leaving the
   * page as it is.
   *
   * @returns nothing
   */
  redrawAccountMenu(): void {
    const doc = this.env.document;
    const el = doc && doc.getElementById
      ? doc.getElementById(PortalShell.ACCOUNTS_ID) : null;
    if (el) {
      el.innerHTML = PortalRuntime.realmLinks(
        PortalShell.accountItems(this.accounts, this.subject, this.t),
        this.prefix);
    }
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
    PortalRuntime.wireDependentSelects(doc);
  }

  // A LIST WHOSE OPTIONS FOLLOW A CHOICE (2026-10-16, `/portal/wallet`'s
  // signing algorithm): a `<select data-depends-on="NAME">` shows only the
  // options whose `data-for` names the checked value of the radios called
  // NAME, and selects the one whose `data-default-for` names it. A hidden
  // option is disabled too, so it is never sent; the page draws the first
  // choice's already, so a browser without this script sends a right value.
  /**
   * Wires every `select[data-depends-on]` in the document to its radios.
   *
   * @param doc - the document
   * @returns nothing
   */
  static wireDependentSelects(doc: Json): void {
    const selects = doc && doc.querySelectorAll
      ? doc.querySelectorAll('select[data-depends-on]') : [];
    for (let i = 0; i < selects.length; i++) {
      const select = selects[i];
      const name = String(select.getAttribute('data-depends-on') || '');
      const radios = doc.querySelectorAll('input[type="radio"][name="' +
                                          name.replace(/"/g, '') + '"]');
      const follow = function (value: string): void {
        const options = select.options || [];
        for (let j = 0; j < options.length; j++) {
          const option = options[j];
          const listed = String(option.getAttribute('data-for') || '')
            .split(' ').indexOf(value) >= 0;
          option.hidden = !listed;
          option.disabled = !listed;
          if (listed && String(option.getAttribute('data-default-for') || '')
            .split(' ').indexOf(value) >= 0) {
            select.value = option.value;
          }
        }
      };
      for (let k = 0; k < radios.length; k++) {
        const radio = radios[k];
        radio.addEventListener('change', function () {
          if (radio.checked) {
            follow(String(radio.value));
          }
        });
      }
    }
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
    // A FORM TYPED IN (#561): a switch asks before it is lost.
    const typed = function (event: Json) {
      if (event && event.target && event.target.form) {
        self.dirty = true;
      }
    };
    this.env.document.addEventListener('input', typed);
    this.env.document.addEventListener('change', typed);
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
