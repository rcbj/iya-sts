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
//   * ONE ACCOUNT PER TAB (#561, with `authn.multipleAccounts` on): the
//     tab's account in sessionStorage sent as `login_hint` on every sign-in,
//     the account menu's Switch, Sign in with another account and Sign
//     out…, and a switch that asks first over unsaved changes, aborts what
//     is in flight, discards every view this tab holds and refuses an answer
//     for another subject (`switchAccount()`, below). With the setting off
//     none of it is drawn or sent.
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
import SpaClient = require('../common/web_spa_client');
import WebPages = require('./web_pages');
import WebShell = require('./web_shell');
import WebForms = require('./web_forms');
import WebAnswers = require('./web_answers');
import WebWebAuthn = require('../common/web_webauthn');
import WebMessages = require('../common/web_messages');
import WebAccounts = require('../common/web_accounts');

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
// A SIGN-IN AGAIN WITHOUT LEAVING THE PAGE (#508): a popup's sign-in is
// told apart at the callback by its state's prefix, and hands its answer
// back to the page that opened it over this channel.
const POPUP_STATE_PREFIX = 'popup.';
const POPUP_CHANNEL = 'sts-console-signin';
// What a page held when a sign-in had to leave it (#508), kept across the
// redirect and put back after, for at most RESTORE_MAX_AGE_MS.
const RESTORE_KEY = 'sts-console-restore';
const RESTORE_MAX_AGE_MS = 30 * 60 * 1000;
// What `sendOnce()` answers when the request needs a sign-in first.
const NEEDS_SIGN_IN = { needsSignIn: true };
// What it answers for a request the tab's account changed under (#561):
// aborted, or answered after the switch — either way not believed.
const ABORTED = { aborted: true };
// Where the tab's account is kept (#561), beside the sign-in's record.
const ACCOUNT_KEY = 'sts-console-account';
// The calls that negotiate the console's language (#543), which are sent
// the browser's own Accept-Language rather than the console's answer.
const LANGUAGE_CALLS = /\/admin-api\/console(\/language)?([?#]|$)/;

/**
 * The static console's runtime: sign-in, DPoP, routing and forms.
 */
class ConsoleRuntime extends SpaClient {
  private shell: Json;
  // The console's translator (#539 phase 5), from the shell's `locale`.
  private t: Json;
  private shellPrefix: string;
  private me: Json;
  private formTable: Json;
  private view: Json;
  // The path and query of the page last drawn: a `popstate` that changes
  // neither is a fragment's, which the browser has already answered.
  private drawnAt: string;
  private spec: Json;
  // The sign-in again in progress, while the session that ended is replaced
  // (#508): its one-use values, the requests waiting on it and the channel
  // the popup answers on. Null when none is.
  private reauth: Json;
  // The form being sent, so a sign-in that has to leave the page knows
  // which one was pressed (#508).
  private submitting: Json;
  // WHETHER A FORM ON THE PAGE DRAWN HAS BEEN TYPED IN (#561): a switch asks
  // first while one has. Set by an `input` or `change` inside a form, and
  // cleared by every drawing.
  private dirty: boolean;
  // THE SIDEBAR SECTION DRAWN OPEN (#750), by its `data-section` key.
  // Null until this load chooses: the first drawing opens the section that
  // holds the page, so a reload shows the list open where the reader is.
  // After that it is the key they opened, or '' when they closed it, and
  // every drawing draws that one open and every other closed. Held here and
  // nowhere else — a page is drawn in place, never loaded, so this object
  // outlives every move between console pages. A new load has no choice to
  // restore and derives one from the page.
  private openSection: string | null;
  // WHAT `GET /admin-api/console` ANSWERED WHEN IT REFUSED THIS TAB'S
  // ACCOUNT (#751): `{ status, json }`, so `route()` draws a page that says
  // so — with the account menu's Switch user group where the setting is on
  // — rather than leaving the tab blank. Null otherwise.
  private shellRefusal: Json;

  /**
   * Makes the runtime.
   *
   * @param env - the browser's objects: `fetch`, `crypto` (WebCrypto),
   *   `location`, `history`, `document`, `sessionStorage`, `navigator`,
   *   `window`, and, for a test, `now` (milliseconds; `Date.now` where left
   *   out) and `formDataOf` (a form's FormData)
   */
  constructor(env: Json) {
    // The OAuth half — the key, the proofs, the tokens, the addresses of the
    // authorization server and the API — is `SpaClient`'s, shared with the
    // portal (#568).
    super(env, ConsoleRuntime.prefixOf(env.location.pathname), {
      clientId: CLIENT_ID, scope: SCOPE,
      elsewhere: { '/oauth2': 'data-sts-oauth', '/admin-api': 'data-sts-api',
                   '/logout': 'data-sts-authn' },
      accountKey: ACCOUNT_KEY });
    this.shell = null;
    this.t = kit.context().t;
    this.shellPrefix = '';
    this.me = null;
    this.formTable = null;
    this.view = null;
    this.drawnAt = '';
    this.spec = null;
    this.reauth = null;
    this.submitting = null;
    this.dirty = false;
    this.openSection = null;
    this.shellRefusal = null;
  }

  // --- paths ---------------------------------------------------------------

  /**
   * Splits a path at the console: the realm prefix before `/admin`.
   *
   * @param pathname - a path, `/realm/acme/admin/users` or `/admin`
   * @returns the prefix, '' in the default realm
   */
  static prefixOf(pathname: string): string {
    return ConsoleRuntime.prefixAt(pathname, '/admin');
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

  // --- the authorization server --------------------------------------------

  /**
   * The origin the management API answers on: this page's, or the API's
   * listener's where it is on another (#472).
   *
   * @returns the origin
   */
  apiOrigin(): string {
    const api = (this.elsewhere || {})['/admin-api'];
    return api ? new URL(api).origin : this.env.location.origin;
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
   * @param extra - for a switch (#561): `login_hint` (the account; '' for
   *   none), `prompt`, `expect` (the subject the answer must be for) and
   *   `another` (a sign-in as another account); nothing otherwise
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
    this.env.location.assign(await this.authorizeUrl(state, verifier,
                                                     asked));
  }

  /**
   * Finishes a sign-in on the callback: checks the state, redeems the code
   * with the verifier and a proof, and goes where the sign-in began.
   *
   * @returns nothing
   */
  async finishSignIn(): Promise<void> {
    // A JARM answer is opened and checked first (#568, `SpaClient`).
    const query = await this.openAuthorizationResponse(
      ConsoleRuntime.queryOf(this.env.location.search));
    // A POPUP'S SIGN-IN (#508) is the opener's to redeem: it holds the
    // verifier and the key, and this window hands the answer back.
    if (String(query.state || '').indexOf(POPUP_STATE_PREFIX) === 0) {
      this.handBackFromPopup(query);
      return;
    }
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
      // THE RETURN TAB of a same-device wallet holds no PKCE record. The
      // tab that opened the console still does, and it redeems the code.
      if (query.code && query.state &&
          await this.handCallbackToStarter(query)) {
        this.env.history.replaceState(null, '',
          this.prefix + '/admin/callback');
        this.drawProblem('Continue in your other tab',
          'This sign-in is finishing in the tab where you opened the ' +
          'console. You can close this one.');
        return;
      }
      // THE SESSION IS ALREADY THERE, as on the portal: the wallet and the
      // passkey finished in this tab. No waiting tab took the callback.
      // Open the console under the old refusal started a fresh request,
      // which that session accepts.
      this.env.history.replaceState(null, '', this.prefix + '/admin');
      await this.beginSignIn('/admin');
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
    if (!await this.nonceMatches(answer.json.id_token, saved.verifier)) {
      this.drawProblem('Signing in failed',
        'The ID Token does not carry the nonce this sign-in sent. Open the ' +
        'console again to sign in.');
      return;
    }
    // A SWITCH IS FOR ONE ACCOUNT (#561): an answer for another subject is
    // refused and its tokens are not kept, so the tab stays the account it
    // was — a reload resumes that one, by its hint.
    if (saved.expect &&
        !ConsoleRuntime.answerIsFor(String(saved.expect),
                                    answer.json.id_token)) {
      this.drawProblem('Switching accounts was refused',
        'The sign-in came back as another account than the one chosen, so ' +
        'this tab did not take it. Open the console again to carry on as ' +
        'the account it was.');
      return;
    }
    const before = this.storedAccount();
    this.keepTokens(answer.json);
    const to = String(saved.returnTo || '/admin');
    this.env.history.replaceState(null, '', this.prefix + to);
    await this.route();
    // What the page held when the sign-in had to leave it (#508).
    this.restorePageState();
    // AN ACCOUNT THIS TAB ADDED TO THE BROWSER is announced, so the other
    // tabs' menus are read again (#561); a reload as the same account is
    // not a change.
    if (saved.another || (before && before.sub !== this.subject)) {
      this.announceAccounts('added');
    }
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

  // ---------------------------------------------------------------------------
  // SIGNING IN AGAIN WITHOUT LOSING THE PAGE (#508, rcbj 2026-10-07).
  //
  // A sign-on session is absolute (`authn.sessionLifetimeS`), so the refresh
  // grant stops working when it ends, and until this the console sent the
  // whole window to sign in: the page came back from its path alone, without
  // its tab, what had been typed or the act that was pressed.
  //
  // **THE CENTRAL SIGN-IN IS STILL THE ONLY WAY BACK** (rcbj: every other
  // gate depends on it). Nothing here authenticates anybody, extends a
  // session or keeps one alive: the popup and the redirect both go to the
  // realm's `/oauth2/authorize`, the sign-in service asks for whatever it
  // asks for, and this page only redeems the code it was issued, with its
  // own PKCE verifier and its own DPoP key.
  //
  // TWO WAYS, the first preferred:
  //   * IN A POPUP. The page stays as it is under a bar that says the
  //     session ended. Its button opens the sign-in in a window of its own
  //     (a click, so no blocker stops it, which is why it is not opened by
  //     itself); that window's callback hands the code back over a
  //     BroadcastChannel and closes, and this page redeems it. Every request
  //     that was waiting — the Save that met the ended session among them —
  //     is then sent, once. A different `sub` coming back sends none of them
  //     and draws the page again for whoever it is.
  //   * ON THIS PAGE, when the reader asks, or the popup cannot work. The
  //     forms' values, the page's address with its tab and which form was
  //     being sent are kept in sessionStorage across the redirect, and put
  //     back after it for the same realm, page and person, with a note that
  //     NOTHING WAS SENT: after a full reload the reader presses Save again,
  //     rather than an act going out that they last saw half an hour ago.
  //     A password, a file, a hidden field and anything named for a secret
  //     are never kept (`keepsField()`).
  // ---------------------------------------------------------------------------
  /**
   * The page's path and query with its fragment, which is the tab it is on.
   *
   * @returns `/admin/...?...#...`
   */
  hereWithFragment(): string {
    return this.here() + String(this.env.location.hash || '');
  }

  /**
   * Keeps what the page holds and sends the window to sign in.
   *
   * @returns nothing
   */
  async leaveToSignIn(): Promise<void> {
    this.savePageState();
    await this.beginSignIn(this.hereWithFragment());
  }

  /**
   * Waits for the person to sign in again, keeping the page.
   *
   * @returns true when the same person is signed in again and a waiting
   *   request may be sent; false when the window left to sign in or a
   *   different person came back
   */
  signInAgain(): Promise<boolean> {
    const self = this;
    // NO PAGE TO KEEP, or no way to open a window: the sign-in leaves, and
    // what the page held goes with it in sessionStorage.
    if (!this.view || !this.subject || !this.env.window ||
        typeof this.env.window.open !== 'function') {
      return this.leaveToSignIn().then(function () {
        return false;
      });
    }
    if (!this.reauth) {
      const BC = this.env.window.BroadcastChannel;
      this.reauth = { waiting: [], verifier: '', state: '', url: '',
                      message: '', popup: null,
                      channel: typeof BC === 'function'
                        ? new BC(POPUP_CHANNEL) : null };
      if (this.reauth.channel) {
        this.reauth.channel.onmessage = function (event: Json) {
          self.onPopupAnswer(event && event.data);
        };
      }
      this.prepareReauth().then(function () {
        const t = self.t;
        // In English where no catalog has it yet (drawReauthBar()).
        self.drawReauthBar(self.reauth && self.reauth.channel ? ''
          : t.has('consoleRuntime.reauth.noPopup')
            ? t.text('consoleRuntime.reauth.noPopup')
            : 'This browser cannot hand a sign-in back from another ' +
              'window, so sign in on this page.');
      }, function () {
        // NO VERIFIER COULD BE MADE: the popup cannot be offered, and the
        // way that is left is the one every browser has.
        self.leaveToSignIn();
      });
    }
    return new Promise(function (resolve) {
      self.reauth.waiting.push(resolve);
    });
  }

  /**
   * Makes the popup's one-use values and its address: a fresh verifier and
   * a state marked as a popup's, for the realm's own authorization request.
   *
   * @returns nothing
   */
  async prepareReauth(): Promise<void> {
    const r = this.reauth;
    if (!r) {
      return;
    }
    r.verifier = this.random(32);
    r.state = POPUP_STATE_PREFIX + this.random(16);
    r.url = await this.authorizeUrl(r.state, r.verifier);
  }

  /**
   * The realm's authorization request for this client.
   *
   * @param state - the state
   * @param verifier - the PKCE verifier
   * @param extra - `login_hint` and `prompt` for a switch (#561), or
   *   nothing
   * @returns the URL
   */
  async authorizeUrl(state: string, verifier: string,
                     extra?: Json): Promise<string> {
    const params: Json = {
      response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: this.url('/admin/callback'), scope: SCOPE,
      state: state, code_challenge: await this.sha256(verifier),
      code_challenge_method: 'S256', resource: this.resource(),
      // OpenID Connect's nonce, which FAPI 1.0 requires (`SpaClient`).
      nonce: await this.nonceFor(verifier)
    };
    // THE TAB'S ACCOUNT (#561), on every sign-in — the popup's and a
    // reload's among them — so the authorization server answers for this
    // tab's session and no other; none where the tab keeps none, which is
    // every tab with the setting off.
    const hint = this.hintFor(extra);
    if (hint) {
      params.login_hint = hint;
    }
    if (extra && extra.prompt) {
      params.prompt = String(extra.prompt);
    }
    // Pushed first where the realm requires it (RFC 9126, #568's
    // `SpaClient.authorizationRequestUrl()`).
    return this.authorizationRequestUrl(params);
  }

  /**
   * Draws the bar that says the session ended, over the page and leaving it
   * as it is.
   *
   * @param message - what the last attempt came to, or ''
   * @returns nothing
   */
  drawReauthBar(message: string): void {
    const r = this.reauth;
    const doc = this.env.document;
    if (!r || !doc || typeof doc.createElement !== 'function' ||
        !doc.body) {
      return;
    }
    r.message = message;
    let bar = doc.getElementById ? doc.getElementById('reauth-bar') : null;
    if (!bar) {
      bar = doc.createElement('div');
      bar.id = 'reauth-bar';
      bar.className = 'reauth';
      bar.setAttribute('role', 'alertdialog');
      bar.setAttribute('aria-labelledby', 'reauth-title');
      doc.body.appendChild(bar);
    }
    // THE WORDS ARE THE READER'S LANGUAGE WHERE A CATALOG HAS THEM (#539
    // phase 5), and the English they always were where none has yet: a
    // sign-in again, or the popup's own page, can be drawn before
    // `GET /admin-api/console` has answered with any catalog.
    const t = this.t;
    bar.innerHTML = '<strong id="reauth-title">' +
      (t.has('consoleRuntime.reauth.title')
        ? t.html('consoleRuntime.reauth.title') : 'Your session has ended.') +
      '</strong> <span>' +
      (t.has('consoleRuntime.reauth.text')
        ? t.html('consoleRuntime.reauth.text')
        : 'Sign in again to carry on. This page and what you typed stay as ' +
          'they are, and what you pressed is sent once you are back.') +
      '</span> ' +
      (r.channel && r.url
        ? '<button type="button" data-reauth="popup">' +
          (t.has('consoleRuntime.reauth.again')
            ? t.html('consoleRuntime.reauth.again') : 'Sign in again') +
          '</button> '
        : '') +
      '<button type="button" data-reauth="page">' +
      (r.channel
        ? (t.has('consoleRuntime.reauth.hereInstead')
            ? t.html('consoleRuntime.reauth.hereInstead')
            : 'Sign in on this page instead')
        : (t.has('consoleRuntime.reauth.here')
            ? t.html('consoleRuntime.reauth.here')
            : 'Sign in on this page')) + '</button>' +
      (message ? ' <span class="reauth-note">' + kit.esc(message) +
                 '</span>' : '');
  }

  /**
   * Takes the bar away.
   *
   * @returns nothing
   */
  removeReauthBar(): void {
    const doc = this.env.document;
    const bar = doc && doc.getElementById
      ? doc.getElementById('reauth-bar') : null;
    if (bar && bar.parentNode) {
      bar.parentNode.removeChild(bar);
    }
  }

  // CALLED FROM THE CLICK ITSELF, with nothing awaited before `open()`: a
  // browser lets a window open only in the task of the press that asked.
  /**
   * Opens the sign-in in a window of its own.
   *
   * @returns nothing
   */
  openReauthPopup(): void {
    const r = this.reauth;
    if (!r || !r.url) {
      return;
    }
    const popup = this.env.window.open(r.url, POPUP_CHANNEL,
                                       'popup,width=560,height=760');
    if (!popup) {
      this.drawReauthBar('The sign-in window was blocked. Allow pop-ups ' +
                         'for this site, or sign in on this page.');
      return;
    }
    r.popup = popup;
    // In English where no catalog has it yet (drawReauthBar()).
    const t = this.t;
    this.drawReauthBar(t.has('consoleRuntime.reauth.finish')
      ? t.text('consoleRuntime.reauth.finish')
      : 'Finish signing in in the window that opened.');
  }

  /**
   * Redeems the code a popup's callback handed back, and lets the waiting
   * requests go — or not, for a different person.
   *
   * @param data - `{ state, code, error, error_description }`
   * @returns nothing
   */
  async onPopupAnswer(data: Json): Promise<void> {
    const r = this.reauth;
    if (!r || !data || String(data.state || '') !== r.state || !r.state) {
      return;
    }
    // ONE ANSWER PER STATE: a second message for it is somebody else's.
    r.state = '';
    if (data.error) {
      await this.prepareReauth();
      this.drawReauthBar('Signing in was refused: ' +
        String(data.error_description || data.error) + '. Try again.');
      return;
    }
    const answer = await this.tokenRequest({
      grant_type: 'authorization_code', code: String(data.code || ''),
      redirect_uri: this.url('/admin/callback'), client_id: CLIENT_ID,
      code_verifier: r.verifier, resource: this.resource()
    });
    if (answer.status !== 200 || !answer.json.access_token) {
      await this.prepareReauth();
      this.drawReauthBar('Signing in failed: ' +
        String(answer.json.error_description || answer.json.error ||
               'the token endpoint answered ' + answer.status) +
        '. Try again.');
      return;
    }
    if (!await this.nonceMatches(answer.json.id_token, r.verifier)) {
      await this.prepareReauth();
      this.drawReauthBar('Signing in failed: the ID Token does not carry ' +
        'the nonce this sign-in sent. Try again.');
      return;
    }
    const before = this.subject;
    const after = ConsoleRuntime.subjectOf(answer.json.id_token);
    const same = ConsoleRuntime.answerIsFor(before, answer.json.id_token);
    // WITH SEVERAL ACCOUNTS IN THE BROWSER (#561) the popup asked for this
    // tab's account by its hint, and an answer for another is refused as a
    // switch's is: this tab stays its account, and the menu switches.
    if (!same && this.accounts.enabled && this.storedAccount()) {
      await this.prepareReauth();
      const t = this.t;
      const kept = this.storedAccount() || {};
      this.drawReauthBar(t.has('consoleRuntime.accounts.otherAccount')
        ? t.text('consoleRuntime.accounts.otherAccount',
                 { user: String(kept.username || '') })
        : 'That sign-in was another account, so this tab did not take it. ' +
          'Sign in again as ' + String(kept.username || '') + ', or switch ' +
          'account from the account menu.');
      return;
    }
    this.keepTokens(answer.json);
    this.reauth = null;
    if (r.channel) {
      r.channel.close();
    }
    this.removeReauthBar();
    r.waiting.forEach(function (resolve) {
      resolve(same);
    });
    if (!same) {
      // A DIFFERENT PERSON: nothing waiting is sent for them, and the page
      // is drawn again with what they may see.
      this.subject = after;
      this.shell = null;
      this.me = null;
      await this.route();
      // In English where no catalog has it yet (drawReauthBar()).
      const t = this.t;
      this.noteOnPage(kit.warn(t.has('consoleRuntime.otherPerson.waiting')
        ? t.html('consoleRuntime.otherPerson.waiting')
        : 'A different person signed in, so what was waiting on this page ' +
          'was not sent.'));
    }
  }

  /**
   * At the callback in a popup: hands the answer to the page that opened
   * it and closes.
   *
   * @param query - the callback's query
   * @returns nothing
   */
  handBackFromPopup(query: Json): void {
    const BC = this.env.window && this.env.window.BroadcastChannel;
    if (this.env.history) {
      // The code leaves the address bar at once.
      this.env.history.replaceState(null, '', this.prefix + '/admin/callback');
    }
    if (typeof BC !== 'function') {
      this.drawProblem('This sign-in cannot be handed back',
        'Close this window and choose Sign in on this page in the console.');
      return;
    }
    const channel = new BC(POPUP_CHANNEL);
    channel.postMessage({ state: String(query.state || ''),
                          code: String(query.code || ''),
                          error: String(query.error || ''),
                          error_description:
                            String(query.error_description || '') });
    channel.close();
    // THE POPUP'S OWN PAGE has fetched no catalog, so this is the English
    // it always was unless one is in hand (drawReauthBar()).
    const t = this.t;
    this.drawProblem(t.has('consoleRuntime.signedInAgain')
                       ? t.text('consoleRuntime.signedInAgain')
                       : 'Signed in again',
      t.has('consoleRuntime.signedInAgain.text')
        ? t.text('consoleRuntime.signedInAgain.text')
        : 'The console carries on where you were. This window can be ' +
          'closed.');
    if (this.env.window && typeof this.env.window.close === 'function') {
      this.env.window.close();
    }
  }

  /**
   * Puts a message at the head of the page drawn.
   *
   * @param html - the message
   * @returns nothing
   */
  noteOnPage(html: string): void {
    const doc = this.env.document;
    const main = doc && doc.querySelector ? doc.querySelector('.main') : null;
    if (main && typeof main.insertAdjacentHTML === 'function') {
      main.insertAdjacentHTML('afterbegin', kit.flash(html));
    }
  }

  // --- what the page held, across a redirect (#508) ------------------------

  /**
   * Whether a form control's value may be kept across a sign-in: never a
   * password, a file, a hidden field, a button, or a control named or
   * marked for a secret.
   *
   * @param el - the control
   * @returns true when it is kept
   */
  static keepsField(el: Json): boolean {
    const name = String((el && el.name) || '');
    const type = String((el && el.type) || '').toLowerCase();
    if (!name || el.disabled) {
      return false;
    }
    if (['password', 'file', 'hidden', 'submit', 'button', 'reset',
         'image'].indexOf(type) >= 0) {
      return false;
    }
    const auto = el.getAttribute
      ? String(el.getAttribute('autocomplete') || '') : '';
    if (/new-password|current-password|one-time-code/.test(auto) ||
        (el.getAttribute && el.getAttribute('data-sensitive') !== null &&
         el.getAttribute('data-sensitive') !== undefined)) {
      return false;
    }
    return !/secret|passw|private|credential|token|otp/i.test(name);
  }

  /**
   * What one form holds, as kept across a sign-in.
   *
   * @param form - the form
   * @param pending - whether it is the form being sent
   * @returns `{ action, pending, fields }`
   */
  static formSnapshot(form: Json, pending: boolean): Json {
    const fields: Json[] = [];
    const els = (form && form.elements) || [];
    for (let i = 0; i < els.length; i++) {
      const el = els[i];
      if (!ConsoleRuntime.keepsField(el)) {
        continue;
      }
      const type = String(el.type || '').toLowerCase();
      if (type === 'checkbox' || type === 'radio') {
        fields.push({ name: el.name, value: String(el.value),
                      checked: !!el.checked });
      } else if (el.multiple && el.options) {
        const values: string[] = [];
        for (let j = 0; j < el.options.length; j++) {
          if (el.options[j].selected) {
            values.push(String(el.options[j].value));
          }
        }
        fields.push({ name: el.name, values: values });
      } else {
        fields.push({ name: el.name, value: String(el.value || '') });
      }
    }
    return { action: String((form.getAttribute &&
                             form.getAttribute('action')) || ''),
             pending: !!pending, fields: fields };
  }

  /**
   * Puts kept values back into the forms drawn: the same form by its place
   * and its address, the same control by its name and order.
   *
   * @param forms - the forms drawn, in document order
   * @param saved - `formSnapshot()`'s answers, in the same order
   * @returns `{ restored, unplaced }`, counts of values
   */
  static restoreForms(forms: Json[], saved: Json[]): Json {
    let restored = 0;
    let unplaced = 0;
    (saved || []).forEach(function (kept, i) {
      const form = forms[i];
      const action = form && form.getAttribute
        ? String(form.getAttribute('action') || '') : '';
      if (!form || action !== String(kept.action || '')) {
        unplaced += (kept.fields || []).length;
        return;
      }
      const byName: Json = {};
      const els = form.elements || [];
      for (let j = 0; j < els.length; j++) {
        if (ConsoleRuntime.keepsField(els[j])) {
          (byName[els[j].name] = byName[els[j].name] || []).push(els[j]);
        }
      }
      const used: Json = {};
      (kept.fields || []).forEach(function (field) {
        const named = byName[field.name] || [];
        if (field.checked !== undefined) {
          const box = named.filter(function (el) {
            return String(el.value) === String(field.value);
          })[0];
          if (!box) {
            unplaced++;
            return;
          }
          box.checked = !!field.checked;
          restored++;
          return;
        }
        const at = used[field.name] || 0;
        used[field.name] = at + 1;
        const el = named[at];
        if (!el) {
          unplaced++;
          return;
        }
        if (field.values && el.options) {
          for (let k = 0; k < el.options.length; k++) {
            el.options[k].selected =
              field.values.indexOf(String(el.options[k].value)) >= 0;
          }
        } else {
          el.value = String(field.value || '');
        }
        restored++;
      });
    });
    return { restored: restored, unplaced: unplaced };
  }

  /**
   * Keeps what the page holds in sessionStorage, for after a redirect.
   *
   * @returns nothing
   */
  savePageState(): void {
    const doc = this.env.document;
    if (!this.view || !this.subject || !doc || !doc.querySelectorAll) {
      return;
    }
    const forms = doc.querySelectorAll('form');
    const kept: Json[] = [];
    for (let i = 0; i < forms.length; i++) {
      kept.push(ConsoleRuntime.formSnapshot(forms[i],
                                            forms[i] === this.submitting));
    }
    try {
      this.env.sessionStorage.setItem(RESTORE_KEY, JSON.stringify({
        prefix: this.prefix, path: this.here(), subject: this.subject,
        at: this.env.now ? this.env.now() : Date.now(), forms: kept }));
    } catch (e) {
      // NO ROOM, or storage refused: the sign-in still goes, and the page
      // comes back without what was typed, as it did before #508.
      return;
    }
  }

  /**
   * After a sign-in that left the page: puts back what it held, for the
   * same realm, page and person, and says nothing was sent.
   *
   * @returns nothing
   */
  restorePageState(): void {
    let saved: Json = null;
    try {
      saved = JSON.parse(this.env.sessionStorage.getItem(RESTORE_KEY) ||
                         'null');
    } catch (e) {
      // Not JSON: nothing this page kept, and nothing to put back.
      saved = null;
    }
    this.env.sessionStorage.removeItem(RESTORE_KEY);
    const now = this.env.now ? this.env.now() : Date.now();
    if (!saved || saved.prefix !== this.prefix ||
        saved.path !== this.here() ||
        now - Number(saved.at || 0) > RESTORE_MAX_AGE_MS) {
      return;
    }
    if (!saved.subject || saved.subject !== this.subject) {
      // In English where no catalog has it yet (drawReauthBar()).
      const t = this.t;
      this.noteOnPage(kit.warn(t.has('consoleRuntime.otherPerson.typed')
        ? t.html('consoleRuntime.otherPerson.typed')
        : 'A different person signed in, so what was typed on this page ' +
          'before was not put back.'));
      return;
    }
    const doc = this.env.document;
    const forms = doc && doc.querySelectorAll ? doc.querySelectorAll('form')
                                              : [];
    const list: Json[] = [];
    for (let i = 0; i < forms.length; i++) {
      list.push(forms[i]);
    }
    const done = ConsoleRuntime.restoreForms(list, saved.forms);
    if (!done.restored && !done.unplaced) {
      return;
    }
    // In English where no catalog has it yet (drawReauthBar()).
    const t = this.t;
    const said = t.has('consoleRuntime.restored');
    this.noteOnPage('<div class="ok">' +
      (said ? t.html('consoleRuntime.restored')
            : 'You are signed in again. What you had typed on this page was ' +
              'put back, and nothing was sent: press the button again to ' +
              'send it.') +
      (done.unplaced
        ? (said ? t.html('consoleRuntime.restored.unplaced',
                         { n: done.unplaced })
                : ' ' + done.unplaced + ' value' +
                  (done.unplaced === 1 ? '' : 's') +
                  ' could not be put back, because the page no longer has ' +
                  'a place for ' + (done.unplaced === 1 ? 'it' : 'them') +
                  '.')
        : '') + '</div>');
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
    // A REQUEST THAT NEEDS A SIGN-IN WAITS FOR ONE (#508) and is then sent,
    // once: the sign-in again (`signInAgain()`) leaves the page as it is,
    // and the act the reader pressed completes when they are back. A false
    // answer is a sign-in that left the page, or a different person.
    const first = await this.sendOnce(method, target, body);
    if (first === ABORTED) {
      return null;
    }
    if (first !== NEEDS_SIGN_IN) {
      return first;
    }
    if (!await this.signInAgain()) {
      return null;
    }
    const second = await this.sendOnce(method, target, body);
    if (second === ABORTED) {
      return null;
    }
    if (second !== NEEDS_SIGN_IN) {
      return second;
    }
    this.accessToken = '';
    await this.leaveToSignIn();
    return null;
  }

  /**
   * Sends one request with the tokens in hand, refreshing them where they
   * have run out.
   *
   * @param method - the method
   * @param target - the absolute URL
   * @param body - as `send()` takes it
   * @returns the response, or NEEDS_SIGN_IN when no token will do
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
      // THE LANGUAGE THE CONSOLE NEGOTIATED, NAMED TO THE API (#543), which
      // translates the prose it writes into a view only when a request
      // names one. Not on the two calls that NEGOTIATE it — the shell and
      // the language chooser's — which must see the browser's own
      // preference, or "follow the browser" would follow the old answer.
      if (this.t && this.t.lang && !LANGUAGE_CALLS.test(target)) {
        headers['Accept-Language'] = this.t.lang;
      }
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
      let res: Json = null;
      try {
        res = await this.env.fetch(target, { method: method,
                                             headers: headers,
                                             body: payload,
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

  // --- language (#539 phase 5) ---------------------------------------------

  /**
   * Builds the console's translator from the shell's `locale` member, and
   * marks the document's language and direction.
   *
   * @param locale - `GET /admin-api/console`'s `locale`
   * @returns nothing
   */
  applyLocale(locale: Json): void {
    this.t = WebMessages.WebTranslator.fromData(locale);
    // AND IT IS THE DEFAULT a helper given no translator falls back to, so
    // a call that forgot `ctx.t` still draws in the reader's language here.
    // `tests/console_web_bundle.js` runs the bundle without this runtime,
    // where such a call draws keys and differs from node: a forgotten `t`
    // is found there rather than hidden here.
    const self = this;
    WebMessages.WebTranslator.setDefault(function () {
      return self.t;
    });
    const root = this.env.document && this.env.document.documentElement;
    if (root && typeof root.setAttribute === 'function') {
      root.setAttribute('lang', this.t.lang);
      root.setAttribute('dir', this.t.dir);
    }
  }

  /**
   * Sets the signed-in administrator's language and draws the page again in
   * it; an empty tag follows the browser. A refusal is said on the page.
   *
   * @param lang - a tag, or ''
   * @returns nothing
   */
  async setLanguage(lang: string): Promise<void> {
    const answer = await this.apiJson('POST', '/admin-api/console/language',
                                      { lang: lang });
    if (!answer || answer.status !== 200 || !answer.json) {
      const why = answer && answer.json && answer.json.errors
        ? answer.json.errors.join(' ') : 'The language could not be set.';
      this.noteOnPage('<div class="err">' + kit.esc(why) + '</div>');
      return;
    }
    this.shell.locale = answer.json.locale;
    this.applyLocale(this.shell.locale);
    await this.route();
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
      this.shellRefusal = null;
      if (!shell || shell.status !== 200) {
        // REFUSED, NOT A SIGN-IN BEGUN (#751): an account switched to that
        // the console will not open for — product mode before the bootstrap
        // administrator's claim (STS-ADMIN-0797), or a policy's refusal —
        // is told so with the browser's other accounts beside it, so the
        // way back is on the page. The list is read as the shell would.
        if (shell) {
          this.shellRefusal = { status: shell.status, json: shell.json };
          await this.readAccounts('');
        }
        return false;
      }
      this.shell = shell.json;
      this.applyLocale(this.shell.locale);
      this.shellPrefix = this.prefix;
      const me = await this.apiJson('GET', '/admin-api/me');
      this.me = me && me.status === 200 ? me.json : {};
      // THE BROWSER'S ACCOUNTS (#561), for the account menu, and the tab's
      // own kept from them; off, nothing is kept and the menu is today's.
      const gate = (this.shell && this.shell.gate) || {};
      await this.readAccounts(String(gate.username || ''));
      const self = this;
      this.listenForAccounts(function () {
        self.redrawAccountMenu();
      });
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
    // A RELOAD HAS NO REMEMBERED SECTION. The choice starts unset, so the
    // first drawing opens the section that holds this page — a reader who
    // reloaded Directory → Applications is shown Directory open. A toggle
    // after that records what they opened, or '' when they closed it, and
    // that is what later drawings use. With no sections in hand yet the
    // choice waits for a drawing that has them.
    if (this.openSection === null && Array.isArray(shell.sections) &&
        shell.sections.length) {
      this.openSection = WebShell.sectionKeyOf(shell.sections, active);
    }
    this.env.document.title = title + ' — IYA STS admin';
    this.env.document.body.innerHTML = ConsoleRuntime.realmLinks(
      WebShell.frame(shell, {
        title: title, active: active, up: up, inner: messages + inner,
        path: this.here(), t: this.t, openSection: this.openSection,
        accounts: this.accounts, subject: this.subject }), this.prefix);
    // A page just drawn holds nothing typed (#561's unsaved-changes test).
    this.dirty = false;
    // EVERY DRAWING replaces the panels a tab's `:target` named — a page
    // routed to, a round trip, an act's answer — so the fragment is made
    // the target again (targetFragment()), and what was drawn is recorded
    // so the `popstate` that causes is known for a fragment's.
    this.drawnAt = this.env.location.pathname + this.env.location.search;
    // A SIGN-IN AGAIN IN PROGRESS (#508) keeps its bar over whatever is
    // drawn while it waits.
    if (this.reauth) {
      this.drawReauthBar(this.reauth.message || '');
    }
    this.targetFragment();
    this.markOpenTabs();
    this.wireCopyButtons();
    this.loadPageScripts();
    this.revealActiveNav();
  }

  // THE TAB BEING READ, ON THE LINK (2026-10-25).
  //
  // The stylesheet names every tab id it knew when it was written and paints
  // that link while its panel is the `:target`. A tab it does not name — a
  // custom listener's, whose id is the operator's — shows its panel and
  // leaves every link looking alike, which is how the Service account
  // sub-tab read until its id was added (#602). After each draw, and
  // whenever the fragment changes without a draw, the link whose panel is
  // the target (or the first, when none in that bar is) gets `tab-current`,
  // the same fill the stylesheet's own rule uses.
  /**
   * Marks the open tab of every tab bar on the page just drawn.
   *
   * @returns nothing
   */
  markOpenTabs(): void {
    const doc = this.env.document;
    if (!doc || typeof doc.querySelectorAll !== 'function' ||
        typeof doc.querySelector !== 'function' ||
        typeof doc.getElementById !== 'function') {
      return;
    }
    const target = doc.querySelector(':target');
    const roots = doc.querySelectorAll('.tabs, .subtabs');
    const count = roots && typeof roots.length === 'number' ? roots.length
      : 0;
    for (let r = 0; r < count; r++) {
      const kids = roots[r] && roots[r].children;
      const nKids = kids && typeof kids.length === 'number' ? kids.length
        : 0;
      let bar = null;
      for (let k = 0; k < nKids; k++) {
        const el = kids[k];
        if (el && el.classList && el.classList.contains('tabbar')) {
          bar = el;
          break;
        }
      }
      if (!bar || !bar.children) {
        continue;
      }
      const links = [];
      for (let c = 0; c < bar.children.length; c++) {
        const el = bar.children[c];
        if (el && String(el.tagName).toUpperCase() === 'A') {
          links.push(el);
        }
      }
      let current = null;
      for (let a = 0; a < links.length; a++) {
        const link = links[a];
        if (link.classList) {
          link.classList.remove('tab-current');
        }
        if (typeof link.removeAttribute === 'function') {
          link.removeAttribute('aria-current');
        }
        const href = String(typeof link.getAttribute === 'function'
          ? (link.getAttribute('href') || '') : '');
        const id = href.charAt(0) === '#' ? href.slice(1) : '';
        const panel = id ? doc.getElementById(id) : null;
        if (panel && target && (target === panel ||
            (typeof panel.contains === 'function' &&
             panel.contains(target)))) {
          current = link;
        }
      }
      if (!current) {
        for (let a = 0; a < links.length; a++) {
          if (!current || (links[a].classList &&
                           links[a].classList.contains('first'))) {
            current = links[a];
            if (links[a].classList &&
                links[a].classList.contains('first')) {
              break;
            }
          }
        }
      }
      if (current && current.classList) {
        current.classList.add('tab-current');
        if (typeof current.setAttribute === 'function') {
          current.setAttribute('aria-current', 'true');
        }
      }
    }
  }

  // THE ACTIVE TAB IS BROUGHT INTO VIEW IN THE SIDEBAR (2026-10-08). The
  // server-drawn console marked it `autofocus` (WebShell.ACTIVE_NAV_FOCUS)
  // and the browser scrolled to it when the page loaded. A page drawn in
  // place by `innerHTML` replaces the nav, whose own scroll starts again at
  // the top, and a browser honours `autofocus` once per document — so a tab
  // far down the list was highlighted out of sight after every click.
  // Only the nav's own scroll is moved, centring the tab where it can be;
  // `scrollIntoView()` would move the page under it too. Where the nav does
  // not scroll (the narrow layout), setting `scrollTop` changes nothing.
  /**
   * Scrolls the sidebar so the page's active tab is in its middle.
   *
   * @returns nothing
   */
  revealActiveNav(): void {
    const doc = this.env.document;
    if (!doc || typeof doc.querySelector !== 'function') {
      return;
    }
    const nav = doc.querySelector('aside.side nav');
    // A CLOSED SECTION HIDES ITS ACTIVE TAB (#750): the tab has no box to
    // centre, so what is brought into view is the section the reader has
    // open, by its heading — and with none open, nothing is moved.
    let here = nav ? nav.querySelector('.here') : null;
    if (here && typeof here.closest === 'function' &&
        here.closest('details:not([open])')) {
      here = nav.querySelector('details[open] > summary');
    }
    if (!nav || !here) {
      return;
    }
    const navBox = nav.getBoundingClientRect();
    const hereBox = here.getBoundingClientRect();
    const offset = (hereBox.top - navBox.top) -
      (nav.clientHeight - hereBox.height) / 2;
    nav.scrollTop = Math.max(0, nav.scrollTop + offset);
  }

  // A SIDEBAR SECTION OPENED OR CLOSED (#750). `toggle` does not bubble, so
  // `start()` listens for it in the capture phase and hands every one here;
  // only a section of the sidebar's nav is acted on. Opening one records it
  // and closes any other: the shared `name` (WebShell.NAV_GROUP) already does
  // that in a browser that knows it, where the loop finds nothing open, and
  // in one that predates it the loop IS the one-open rule. Closing the one
  // recorded forgets it; the `toggle` for a section the browser closed
  // because another opened does not, whichever order the two arrive in.
  /**
   * Records the sidebar section opened, and closes the others.
   *
   * @param target - the element a `toggle` event was fired at
   * @returns nothing
   */
  onNavToggle(target: Json): void {
    if (!target || !target.classList ||
        !target.classList.contains('navsec') ||
        typeof target.getAttribute !== 'function') {
      return;
    }
    const key = String(target.getAttribute('data-section') || '');
    if (!target.open) {
      if (this.openSection === key) {
        this.openSection = '';
      }
      return;
    }
    this.openSection = key;
    const doc = this.env.document;
    const open = doc && doc.querySelectorAll
      ? doc.querySelectorAll('aside.side details.navsec[open]') : [];
    for (let i = 0; i < open.length; i++) {
      if (open[i] !== target) {
        open[i].open = false;
      }
    }
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

  // A PAGE UNDER A REALM'S PREFIX LINKS INTO THAT REALM: the static console
  // draws root-relative addresses and prefixes them itself, as the
  // server-rendered console's `withRealmLinks()` did —
  // `ConsoleRuntime.realmLinks()` is `WebPage`'s (#570), inherited.

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
      kit.esc(this.prefix + '/admin') + '">' +
      // In English where no catalog has it yet (drawReauthBar()).
      (this.t.has('consoleRuntime.openConsole')
        ? this.t.html('consoleRuntime.openConsole') : 'Open the console') +
      '</a></p>' +
      '</div></div></div>';
  }

  // A PERSON THE CONSOLE WILL NOT OPEN FOR (#751). A person holding no
  // console role is answered the frame with nothing in it (#454) and gets
  // the gate's banner and the menu as any reader does; this is the other
  // case, `GET /admin-api/console` itself refused, which until #751 left
  // the tab blank — and a tab just switched to such an account, with no
  // menu to switch back from, was a dead end. The page says what the API
  // answered, and with several accounts on it carries the Switch user group
  // (`WebShell.accountItems()`, in `#sts-account-switch` so a change in
  // another tab redraws it) and Sign out; off, Sign out alone. Nothing here
  // is a boundary: the API refused, and still refuses.
  /**
   * Draws the page for an account the console's shell answer refused.
   *
   * @param refusal - `{ status, json }`, what the shell answer was
   * @returns nothing
   */
  drawShellRefused(refusal: Json): void {
    const t = this.t;
    const json = (refusal && refusal.json) || {};
    const why = String(json.error_description || json.error || '');
    const title = t.has('consoleRuntime.accounts.refused.title')
      ? t.text('consoleRuntime.accounts.refused.title')
      : 'The console will not open for this account';
    const text = (t.has('consoleRuntime.accounts.refused.text')
      ? t.text('consoleRuntime.accounts.refused.text',
               { status: String(refusal.status) })
      : 'The management API answered ' + String(refusal.status) +
        ' for the account this tab is signed in as.') +
      (why ? ' ' + why : '');
    const menu = this.accounts.enabled
      ? '<div id="' + WebShell.ACCOUNTS_ID + '" class="usermenuaccounts">' +
        WebShell.accountItems(this.accounts, this.subject, t) + '</div>'
      : '';
    this.env.document.title = title + ' — IYA STS admin';
    this.env.document.body.innerHTML = ConsoleRuntime.realmLinks(
      '<div class="shell"><div class="main"><div class="card"><h1>' +
      kit.esc(title) + '</h1>' + kit.note(kit.esc(text)) + menu +
      WebShell.signOutControl({ session: true }, t) +
      '</div></div></div>', this.prefix);
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
    // AN ADDRESS WHOSE CONTENT MOVED (#752) — the Credential status tab of
    // `/admin/vc`, now Monitoring → Verifiable Credentials — is replaced in
    // place by the page's, before a sign-in keeps it to come back to or
    // anything is fetched, so a bookmark lands on the content. Its query
    // goes with it; its fragment named the tab that is gone.
    const moved = path
      ? WebPages.movedTo(path, this.env.location.hash) : null;
    if (moved) {
      this.env.history.replaceState(null, '', this.prefix + moved +
                                    this.env.location.search);
      await this.route();
      return;
    }
    if (!this.accessToken) {
      await this.beginSignIn(this.hereWithFragment());
      return;
    }
    // THE IDENTITY THIS PAGE IS DRAWN FOR (#561): a switch while it is being
    // fetched leaves it undrawn.
    const identity = this.identity;
    if (!await this.ensureShell() || identity !== this.identity) {
      if (identity === this.identity && this.shellRefusal) {
        this.drawShellRefused(this.shellRefusal);
      }
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
      this.draw(WebPages.titleOf(page, this.t), page.path,
        kit.warn('The management API ' +
        'answered ' + answer.status + ' for <code>' +
        kit.esc(page.operation) + '</code>.' +
        (answer.json && answer.json.error
          ? ' ' + kit.esc(answer.json.error_description ||
                          answer.json.error) : ''), 'It could not be drawn'),
        null);
      return;
    }
    let json = answer.json;
    if (page.compose) {
      const self = this;
      const asked = WebPages.composeRequests(page, query);
      const answers = await Promise.all(asked.map(async function (one) {
        const search = new URLSearchParams(one.params).toString();
        return { member: one.member, operation: one.operation,
          answer: await self.apiJson('GET', one.operation +
            (search ? '?' + search : '')) };
      }));
      if (identity !== this.identity) {
        return;
      }
      const failed = answers.filter(function (one) {
        return !one.answer || one.answer.status !== 200 || !one.answer.json;
      })[0];
      if (failed) {
        const status = failed.answer ? failed.answer.status : 'unavailable';
        const detail = failed.answer && failed.answer.json &&
          failed.answer.json.error
          ? ' ' + kit.esc(failed.answer.json.error_description ||
                          failed.answer.json.error) : '';
        this.draw(WebPages.titleOf(page, this.t), page.path,
          kit.warn('The management API answered ' + status + ' for <code>' +
          kit.esc(failed.operation) + '</code>.' + detail,
          'It could not be drawn'), null);
        return;
      }
      json = Object.assign({}, json);
      answers.forEach(function (one) {
        json[one.member] = one.answer.json;
      });
    }
    this.view = { page: page, json: json, query: query };
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
  // `targetFragment()` is `WebPage`'s (#570), inherited.

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
    const ctx = kit.context(query, write, this.t);
    const drilled = page.drill && query[page.drill.param];
    const up = drilled
      ? { href: page.path + kit.queryWith(kit.listViewOf(page.path, query),
                                          {}),
          label: (this.shell.navLabels || {})[page.path] || page.title,
          leaf: String(query[page.drill.param]),
          filtered: Object.keys(kit.listViewOf(page.path, query)).length > 0 }
      : null;
    // The title in the reader's language (#539 phase 5).
    const title = WebPages.titleOf(page, this.t);
    this.draw(drilled ? title + ' ' + query[page.drill.param] : title,
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

  // AN UNTICKED CHECKBOX POSTS NOTHING, which the server-drawn console's
  // handlers read as "no" (a policy save was told `via: 'console'`). An
  // operation that takes the whole of a thing — Directory → Policies'
  // profiles, where a save REPLACES the profile and every field is
  // required — refused a save with any box unticked (rcbj, 2026-10-12:
  // unticking "Allow a passkey sign-in with no username"). So the names
  // of the form's unticked boxes are handed to `shapeFields()`, which
  // sends `false` for each one the operation takes as a boolean.
  /**
   * The names of a form's checkboxes that are not ticked, where no box of
   * that name is.
   *
   * @param form - the form element
   * @returns the names
   */
  static uncheckedBoxes(form: Json): string[] {
    if (!form || typeof form.querySelectorAll !== 'function') {
      return [];
    }
    const boxes = form.querySelectorAll('input[type="checkbox"][name]');
    const ticked: Json = {};
    const names: string[] = [];
    for (let i = 0; i < boxes.length; i++) {
      // A DISABLED BOX COUNTS TOO: a form leaves it out whether ticked or
      // not, and Directory → Policies disables a field that cannot be
      // turned on here (an emailed factor with no mail), whose save still
      // needs its value — off.
      const box = boxes[i];
      if (box.checked) {
        ticked[box.name] = true;
      } else if (names.indexOf(box.name) < 0) {
        names.push(box.name);
      }
    }
    return names.filter(function (name: string) {
      return !ticked[name];
    });
  }

  /**
   * Shapes a form's fields to an operation's request schema.
   *
   * @param fields - the form's fields
   * @param schema - the operation's request schema, or null for none
   * @param unchecked - optional; the form's unticked checkboxes' names, sent
   *   as `false` where the schema takes that member as a boolean
   * @returns the body to send
   */
  shapeFields(fields: Json, schema: Json, unchecked?: string[]): Json {
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
      // empty string — a pattern, a format, a minimum length, a type that is
      // not a string — as the server-rendered console's form parser read it.
      // It is kept where a string is all the schema asks, so a field can
      // still be cleared.
      if (value === '' && (prop.pattern || prop.format || prop.minLength > 0 ||
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
    (unchecked || []).forEach(function (name: string) {
      if (name in out || !has(name)) {
        return;
      }
      // ANY MEMBER THAT TAKES A BOOLEAN, whether its `type` says so or a
      // branch of `oneOf`/`anyOf` does: the policy kinds declare each
      // yes/no field as a boolean OR a string (`TRUE`/`FALSE` from a form),
      // and those are exactly the fields the passkey profile refused.
      const prop = self.deref(schema.properties[name]) || {};
      const branches = [prop].concat(prop.oneOf || [], prop.anyOf || [])
        .map(function (one: Json) {
          return self.deref(one) || {};
        });
      const takesBoolean = branches.some(function (one: Json) {
        return [].concat(one.type || []).indexOf('boolean') >= 0;
      });
      if (takesBoolean) {
        out[name] = false;
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
    if (form && form.getAttribute &&
        (form.getAttribute('data-admin-passkey-upgrade') === 'true' ||
         form.getAttribute('data-admin-passkey-enrolment') === 'true')) {
      if (form.getAttribute('data-admin-passkey-upgrade') === 'true') {
      await this.adminPasskeyUpgrade(fields);
      } else {
      await this.adminPasskeyEnrolment(fields);
      }
      return;
    }
    // ENTER IN A FIELD'S SEARCH BOX SEARCHES (#459). Enter presses the
    // form's first submit button — the hidden default, which is Save — and
    // somebody who typed a name to look for has not asked to save the tab.
    const typedIn = this.env.document && this.env.document.activeElement;
    const findIn = typedIn && typedIn.getAttribute
      ? String(typedIn.getAttribute('data-fg-find') || '') : '';
    if (findIn && (!submitter || /\bdefault-submit\b/.test(
      String(submitter.className || '')))) {
      fields.fgsearch = findIn;
    }
    // A PRESS IN ANOTHER FIELD IS MOVING TO IT (#462): a "+" or a bin
    // elsewhere closes an open search even in a browser that does not
    // focus a button on click, where no `focusin` came. The press's own
    // place decides — the search box for Enter, else the button.
    if (submitter || findIn) {
      this.closeOtherSearches(findIn ? typedIn : submitter);
    }
    // A FIELD'S SEARCH (#459) is a round trip that needs data: the list
    // operation's page of five, drawn under the box. It writes nothing.
    if (page && this.view && WebAnswers.isFieldSearch(page, fields)) {
      if (page === WebAnswers.SERVICE_ACCOUNT_PAGE) {
        await this.ownerSearch(fields);
        return;
      }
      if (page === WebAnswers.GROUP_OWNERS_PAGE) {
        await this.groupOwnerSearch(fields);
        return;
      }
      if (page === WebAnswers.ROLE_OWNERS_PAGE) {
        await this.groupOwnerSearch(fields, 'role', 'roleOwners');
        return;
      }
      if (page === WebAnswers.APPLICATION_OWNERS_PAGE) {
        await this.groupOwnerSearch(fields, 'page', 'applicationOwners');
        return;
      }
      if (page === WebAnswers.POLICIES_PAGE) {
        await this.policySearch(fields);
        return;
      }
      await this.fieldSearch(fields);
      return;
    }
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
      const drawn = WebAnswers.filled(fields, invent.json, this.view.json,
                                      this.t);
      this.view.json = drawn.json;
      this.drawView(null, drawn.banner);
      return;
    }
    const operation = page ? WebForms.resolve(
      this.formTable, page + target.hash, action)
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
          body: this.shapeFields(fields, await this.requestSchema(operation),
                                 ConsoleRuntime.uncheckedBoxes(form)) };
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
                 this.env.location.origin }, this.t);
    if (once) {
      this.view = null;
      // ITS TRAIL LEADS BACK (#1068). With no `up` the section was the last
      // crumb, which is never a link, so the page had no way back to the
      // section it was reached from. The section is a link now, and a page
      // about a person names that person too (`WebAnswers.personTrail()`).
      this.draw(once.title, once.active, once.html,
                once.up || { href: once.active, leaf: once.title }, '');
      return;
    }
    // A REDRAW FROM THE ANSWER: a refused create or edit with every box as
    // it was, a generated secret or a loaded document in its form, the
    // workbench's next draft, a resolution under the form that asked.
    const again = this.view
      ? WebAnswers.redraw(page, action, fields, json, this.view.json, this.t)
      : null;
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

  // The administrator's browser performs both ceremonies; the API validates
  // each against the pending upgrade, and keeps the classical key until the
  // ML-DSA registration is verified.
  /**
   * Proves and upgrades a person's passkey from the admin console.
   *
   * @param fields - the person and classical credential id
   * @returns nothing
   */
  async adminPasskeyUpgrade(fields: Json): Promise<void> {
    const who = String(fields.user || '');
    const base = this.here().replace(/([?&])(notice|error)=[^&]*/g, '$1')
      .replace(/[?&]+$/, '');
    const report = async (kind: string, message: string) => {
      await this.go(base + (base.indexOf('?') < 0 ? '?' : '&') + kind + '=' +
                    encodeURIComponent(message));
    };
    let upgradeId = '';
    try {
      const begun = await this.apiJson('POST',
        '/admin-api/users/begin-passkey-upgrade', {
          user: who, credentialId: String(fields.credentialId || '') });
      if (!begun) { return; }
      if (begun.status >= 400 || !begun.json || !begun.json.ok) {
        throw new Error(((begun.json && begun.json.errors) || []).join(' ') ||
                        'The upgrade could not be started.');
      }
      upgradeId = String(begun.json.upgradeId || '');
      const proof = begun.json.ceremony;
      const asserted = await this.env.navigator.credentials.get({ publicKey: {
        challenge: WebWebAuthn.bytes(proof.challenge), rpId: proof.rpId,
        allowCredentials: [{ type: 'public-key',
          id: WebWebAuthn.bytes(proof.allow) }],
        userVerification: (proof.options && proof.options.userVerification) ||
                          'preferred' } });
      if (!asserted) { throw new Error('The passkey did not answer.'); }
      const proved = await this.apiJson('POST',
        '/admin-api/users/prove-passkey-upgrade', {
          user: who, upgradeId: upgradeId,
          credential: JSON.stringify(WebWebAuthn.asserted(asserted)) });
      if (!proved) { return; }
      if (proved.status >= 400 || !proved.json || !proved.json.ok) {
        throw new Error(((proved.json && proved.json.errors) || []).join(' ') ||
                        'The passkey proof was refused.');
      }
      const registration = proved.json.ceremony;
      const options: Json = Object.assign({}, registration.options || {});
      options.challenge = WebWebAuthn.bytes(registration.challenge);
      options.user = Object.assign({}, registration.user, {
        id: WebWebAuthn.bytes(registration.user.id) });
      options.pubKeyCredParams = (options.algorithms || []).map(function (alg) {
        return { type: 'public-key', alg: alg };
      });
      delete options.algorithms;
      options.excludeCredentials = (registration.exclude || []).map(
        function (id) { return { type: 'public-key',
          id: WebWebAuthn.bytes(id) }; });
      options.extensions = (options.credProps || options.minPinLength)
        ? Object.assign(options.credProps ? { credProps: true } : {},
                        options.minPinLength ? { minPinLength: true } : {})
        : undefined;
      delete options.credProps;
      delete options.minPinLength;
      const made = await this.env.navigator.credentials.create({
        publicKey: options });
      if (!made) { throw new Error('The authenticator refused registration.'); }
      const finished = await this.apiJson('POST',
        '/admin-api/users/finish-passkey-upgrade', { user: who,
          upgradeId: upgradeId,
          credential: JSON.stringify(WebWebAuthn.created(made)) });
      if (!finished) { return; }
      if (finished.status >= 400 || !finished.json || !finished.json.ok) {
        throw new Error(((finished.json && finished.json.errors) || [])
          .join(' ') || 'The passkey could not be upgraded.');
      }
      await report('notice', finished.json.message ||
        'The passkey was upgraded.');
    } catch (e) {
      if (upgradeId) {
        await this.apiJson('POST', '/admin-api/users/cancel-passkey-upgrade',
                           { user: who }).catch(function () { return null; });
      }
      await report('error', String((e && e.message) || e));
    }
  }
  // AN ADMINISTRATOR'S PASSKEY ENROLMENT (#945) runs the WebAuthn ceremony
  // in this browser while every API call still goes through the console's
  // DPoP client. The server binds the one-use challenge to this administrator
  // and the named person; a browser refusal is sent to finish to spend it.
  /**
   * Runs the begin, browser registration and finish steps for a person.
   *
   * @param fields - the submitted user and role
   * @returns nothing
   */
  async adminPasskeyEnrolment(fields: Json): Promise<void> {
    const who = String(fields.user || fields.username || '');
    const back = this.here().replace(/([?&])(notice|error)=[^&]*/g, '$1')
      .replace(/[?&]+$/, '');
    const report = async function (self, kind, message) {
      const join = back.indexOf('?') < 0 ? '?' : '&';
      await self.go(back + join + kind + '=' + encodeURIComponent(message));
    };
    const begun = await this.apiJson('POST',
      '/admin-api/users/begin-passkey-enrolment',
      { user: who, role: String(fields.role || 'mfa'),
        lane: String(fields.lane || ''), kind: String(fields.kind || '') });
    if (!begun) {
      return;
    }
    const ceremony = begun.json && begun.json.ceremony;
    if (begun.status >= 400 || !begun.json || !begun.json.ok || !ceremony) {
      const errors = begun.json && begun.json.errors;
      await report(this, 'error', errors && errors[0]
        ? errors[0] : 'The passkey enrolment could not be started.');
      return;
    }
    let credential: Json;
    try {
      if (!this.env.navigator || !this.env.navigator.credentials ||
          typeof this.env.navigator.credentials.create !== 'function') {
        throw new Error('This browser cannot create a WebAuthn credential.');
      }
      const publicKey: Json = Object.assign({}, ceremony.options || {});
      publicKey.challenge = WebWebAuthn.bytes(ceremony.challenge);
      publicKey.rp = publicKey.rp || { id: ceremony.rpId, name: 'Iya STS' };
      publicKey.user = Object.assign({}, ceremony.user, {
        id: WebWebAuthn.bytes(ceremony.user.id) });
      publicKey.pubKeyCredParams = (publicKey.algorithms || []).map(
        function (alg) { return { type: 'public-key', alg: alg }; });
      delete publicKey.algorithms;
      publicKey.excludeCredentials = (ceremony.exclude || []).map(function (id) {
        return { type: 'public-key', id: WebWebAuthn.bytes(id) };
      });
      publicKey.extensions = (publicKey.credProps || publicKey.minPinLength)
        ? Object.assign(publicKey.credProps ? { credProps: true } : {},
                        publicKey.minPinLength ? { minPinLength: true } : {})
        : undefined;
      delete publicKey.credProps;
      delete publicKey.minPinLength;
      const made = await this.env.navigator.credentials.create({
        publicKey: publicKey });
      if (!made) {
        throw new Error('The authenticator did not create a credential.');
      }
      credential = WebWebAuthn.created(made);
    } catch (e) {
      credential = { error: String((e && e.name) || 'NotAllowedError'),
        message: String((e && e.message) || 'The authenticator refused.') };
    }
    const finished = await this.apiJson('POST',
      '/admin-api/users/finish-passkey-enrolment', {
        user: who, enrolmentId: begun.json.enrolmentId,
        credential: JSON.stringify(credential) });
    if (!finished) {
      return;
    }
    if (finished.status >= 400 || !finished.json || !finished.json.ok) {
      const errors = finished.json && finished.json.errors;
      await report(this, 'error', errors && errors[0]
        ? errors[0] : 'The passkey could not be registered. Start again.');
      return;
    }
    await report(this, 'notice', 'Passkey enrolled for ' + who + '.');
  }

  // A FIELD'S SEARCH (#459): `WebAnswers` reads the press and builds the
  // address; here the list operation is asked and the page drawn again with
  // every box as it was (and, for an Add, one more), the results in the
  // cell's state, and the focus put back in the search box — the cell is
  // open while focus is inside it (`:focus-within`), and a redraw replaces
  // the element that had it.
  /**
   * Runs a field search's Find, Previous, Next or Add and draws the result.
   *
   * @param fields - the form's fields, the pressed button's among them
   * @returns nothing
   */
  async fieldSearch(fields: Json): Promise<void> {
    const asked = WebAnswers.fieldSearchOf(fields);
    const config = (this.view.json && this.view.json.page &&
                    this.view.json.page.config) || {};
    const kind = String((config.fieldSearches || {})[asked.attribute] || '');
    if (!kind) {
      return;
    }
    const drafted = asked.add
      ? WebAnswers.withValueAdded(fields, asked.attribute, asked.add)
      : fields;
    const held = kit.gridValuesFromDraft(drafted)[asked.attribute] || [];
    // AN APPLICATION SEARCH LEAVES OUT THE APPLICATION ITSELF, which neither
    // list may name (STS-REG-0335); both leave out what the list holds.
    // A `parties` search (#461) replaces ONE value, so it leaves out only
    // the application itself, and only from the applications it finds.
    const exclude = kind === 'parties'
      ? [String(fields.application || '')]
      : (kind === 'applications'
        ? [String(fields.application || '')] : []).concat(held);
    const answer = await this.apiJson('GET',
      WebAnswers.fieldSearchPath(kind, asked, exclude));
    const found = WebAnswers.fieldSearchFound(kind, asked,
      answer && answer.status === 200 ? answer.json : null);
    const before = (this.view.json && this.view.json.state) || {};
    const finds = Object.assign({}, before.finds || {});
    finds[asked.attribute] = found;
    this.view.json = Object.assign({}, this.view.json, {
      state: { draft: drafted, finds: finds } });
    this.drawView(null, '');
    // THE CELL STAYS OPEN BY ITS CLASS (`fg-search-open`, #462), drawn from
    // `finds`; focus in its box is a convenience on top, so typing can go
    // on. Put back after the drawing has settled: `draw()` re-navigates to
    // the fragment (`targetFragment()`), and a focus given before that is
    // lost to it, which is what closed the cell under #459.
    const doc = this.env.document;
    const attribute = asked.attribute;
    const refocus = function () {
      const box = doc.getElementById('fgq-' + attribute);
      if (box && box.focus) {
        box.focus({ preventScroll: true });
      }
    };
    refocus();
    if (this.env.window && this.env.window.setTimeout) {
      this.env.window.setTimeout(refocus, 0);
    }
  }

  // A NAMED PASSKEY PROFILE'S APPLICATION SEARCH (#609): the field search's
  // Find, Previous, Next and Add on Directory → Policies. The Applications
  // list is asked for a page of five, leaving out what the form's
  // applications box already holds, and the page drawn again with that
  // form's posted fields as its draft (`state.policyDrafts`, by the search's
  // key) — an Add appends the application's IDENTIFIER to the box — and the
  // results in `state.finds`, as the grid keeps them. Nothing is written
  // until the form's Save, which writes `stsPasskeySelectApplication` as it
  // always did.
  /**
   * Runs a named policy's application search and draws the result.
   *
   * @param fields - the form's fields, the pressed button's among them
   * @returns nothing
   */
  async policySearch(fields: Json): Promise<void> {
    const asked = WebAnswers.fieldSearchOf(fields);
    const drafted = Object.assign({}, fields);
    delete drafted.fgsearch;
    delete drafted.fgadd;
    const text = WebAnswers.one(fields, 'selectApplications');
    drafted.selectApplications = asked.add
      ? WebAnswers.withListedValue(text, asked.add)
      : text;
    const held = WebAnswers.listedValues(drafted.selectApplications);
    const answer = await this.apiJson('GET',
      WebAnswers.fieldSearchPath('policy-applications', asked, held));
    const found = WebAnswers.fieldSearchFound('policy-applications', asked,
      answer && answer.status === 200 ? answer.json : null);
    const before = (this.view.json && this.view.json.state) || {};
    const finds = Object.assign({}, before.finds || {});
    finds[asked.attribute] = found;
    const drafts = Object.assign({}, before.policyDrafts || {});
    drafts[asked.attribute] = drafted;
    this.view.json = Object.assign({}, this.view.json, {
      state: Object.assign({}, before, { finds: finds,
                                         policyDrafts: drafts }) });
    this.drawView(null, '');
    const doc = this.env.document;
    const attribute = asked.attribute;
    const refocus = function () {
      const box = doc.getElementById('fgq-' + attribute);
      if (box && box.focus) {
        box.focus({ preventScroll: true });
      }
    };
    refocus();
    if (this.env.window && this.env.window.setTimeout) {
      this.env.window.setTimeout(refocus, 0);
    }
  }

  // A SERVICE ACCOUNT'S OWNER SEARCH (#600): the field search's Find,
  // Previous, Next and Add, for the person page's service account form. The
  // Users or the Groups list is asked for a page of five, and the form drawn
  // again from its draft (`state.serviceAccount`) — an Add puts the owner in
  // the table — with the focus back in the search box. Nothing is written
  // until the form's Save.
  /**
   * Runs an owner search's Find, Previous, Next or Add and draws the result.
   *
   * @param fields - the form's fields, the pressed button's among them
   * @returns nothing
   */
  async ownerSearch(fields: Json): Promise<void> {
    const asked = WebAnswers.fieldSearchOf(fields);
    const before = (this.view.json && this.view.json.state) || {};
    // THE PUSH DESTINATION'S SEARCH (#602) is the same press on the other
    // list; each keeps the other's results.
    const kind = asked.attribute === 'destinations' ? 'destinations'
                                                     : 'owners';
    let draft = WebAnswers.serviceAccountDraftOf(fields,
                                                 before.serviceAccount);
    if (asked.add && kind === 'owners') {
      draft = WebAnswers.withOwnerAdded(draft, asked.add);
    }
    if (asked.add && kind === 'destinations') {
      draft = WebAnswers.withDestinationUsed(draft, asked.add);
    }
    // ON A SERVICE ACCOUNT the table is the account's, written at once
    // (#602), and the form carries no `owner` rows: what to leave out of a
    // groups search is what the account holds.
    const account = this.view.json && this.view.json.serviceAccount;
    const held = account
      ? (account.owners || []).map(function (one: Json) {
        return String(one.dn);
      })
      : draft.owners;
    const answer = await this.apiJson('GET',
      WebAnswers.fieldSearchPath(kind, asked, held));
    const found = WebAnswers.fieldSearchFound(kind, asked,
      answer && answer.status === 200 ? answer.json : null);
    if (kind === 'destinations') {
      draft.destFind = found;
    } else {
      draft.find = found;
    }
    draft.at = kind === 'destinations' ? 'destination' : 'owners';
    this.view.json = Object.assign({}, this.view.json, {
      state: Object.assign({}, before, { serviceAccount: draft }) });
    this.drawView(null, '');
    const doc = this.env.document;
    const refocus = function () {
      const box = doc.getElementById('fgq-' + kind);
      if (box && box.focus) {
        box.focus({ preventScroll: true });
      }
    };
    refocus();
    if (this.env.window && this.env.window.setTimeout) {
      this.env.window.setTimeout(refocus, 0);
    }
  }

  // A GROUP'S OWNER SEARCH (#603): the service account's people-or-groups
  // search on a group's Owners tab. The Users or the Groups list is asked for
  // a page of five — a groups search leaving out the group's owners and the
  // group itself — and the tab drawn again with the results, the focus back
  // in the box. Nothing is written: the results' Add writes, as an act.
  /**
   * Runs a group owner search's Find, Previous or Next and draws the result.
   *
   * @param fields - the form's fields, the pressed button's among them
   * @param holder - optional; the view member holding the owners (`group`,
   *   or `role` since #604)
   * @param stateKey - optional; the page state member (`groupOwners`)
   * @returns nothing
   */
  async groupOwnerSearch(fields: Json, holder?: string,
                         stateKey?: string): Promise<void> {
    // A ROLE'S (#604) is the same search: the role's view in `role`, its
    // state in `roleOwners`; a role's DN names nothing a search finds.
    const asked = WebAnswers.fieldSearchOf(fields);
    const before = (this.view.json && this.view.json.state) || {};
    const group = (this.view.json && this.view.json[holder || 'group']) || {};
    const held = (group.owners || []).map(function (one: Json) {
      return String(one.dn);
    }).concat(group.dn ? [String(group.dn)] : []);
    const answer = await this.apiJson('GET',
      WebAnswers.fieldSearchPath('owners', asked, held));
    const found = WebAnswers.fieldSearchFound('owners', asked,
      answer && answer.status === 200 ? answer.json : null);
    this.view.json = Object.assign({}, this.view.json, {
      state: Object.assign({}, before, {
        [stateKey || 'groupOwners']: { find: found, notice: '',
                                       error: [] } }) });
    this.drawView(null, '');
    const doc = this.env.document;
    const refocus = function () {
      const box = doc.getElementById('fgq-owners');
      if (box && box.focus) {
        box.focus({ preventScroll: true });
      }
    };
    refocus();
    if (this.env.window && this.env.window.setTimeout) {
      this.env.window.setTimeout(refocus, 0);
    }
  }

  // A FIELD'S SEARCH CLOSES WHEN THE READER MOVES TO ANOTHER FIELD (#462,
  // rcbj: "if they move to another field, minimize it back"). On `focusin`
  // anywhere, every open search cell that does not contain the newly
  // focused element loses `fg-search-open` — and its results leave the
  // page's state, so the next redraw (a "+" in another cell) does not open
  // it again. `focusin` rather than `focusout` or `blur`: those fire when a
  // result's Add or Next is clicked in a browser that focuses buttons, and
  // in one that does not, nothing moves at all, which is right.
  /**
   * Closes every open field search but the one focus moved into.
   *
   * @param target - the element that received focus
   * @returns nothing
   */
  closeOtherSearches(target: Json): void {
    const doc = this.env.document;
    const open = doc.querySelectorAll ? doc.querySelectorAll('.fg-search-open')
                                      : [];
    const state = this.view && this.view.json && this.view.json.state;
    const finds = Object.assign({}, (state && state.finds) || {});
    let closed = false;
    for (let i = 0; i < open.length; i++) {
      const cell = open[i];
      if (target && cell.contains && cell.contains(target)) {
        continue;
      }
      cell.classList.remove('fg-search-open');
      delete finds[String(cell.id || '').replace(/^fgc-/, '')];
      closed = true;
    }
    if (closed && state) {
      this.view.json = Object.assign({}, this.view.json, {
        state: Object.assign({}, state, { finds: finds }) });
    }
  }

  // `saveBase64()` is `WebPage`'s (#570), inherited.

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
    // THE SESSION-ENDED BAR'S TWO BUTTONS (#508). The popup is opened here,
    // in the click's own task, or a browser blocks it.
    const pressed = event.target && event.target.getAttribute
      ? event.target.getAttribute('data-reauth') : null;
    if (pressed && this.reauth) {
      event.preventDefault();
      if (pressed === 'popup') {
        this.openReauthPopup();
      } else {
        this.leaveToSignIn();
      }
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
    // A LINK TO AN ADDRESS WHOSE CONTENT MOVED (#752) goes to the page —
    // checked first, because a link to a gone tab of the page being read
    // would otherwise only change the fragment.
    const moved = WebPages.movedTo(page, url.hash);
    if (moved) {
      this.go(moved + url.search);
      return;
    }
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
    // WHICH FORM WAS PRESSED, for a sign-in that has to leave the page
    // while it is being sent (#508).
    const self = this;
    this.submitting = form;
    const done = function () {
      if (self.submitting === form) {
        self.submitting = null;
      }
    };
    this.submit(form, event.submitter || null).then(done, function (e) {
      done();
      throw e;
    });
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
    // WHICH ACCOUNT (#561): with several in the browser, the sign-out is
    // told the tab's, which it preselects; with the setting off the address
    // is the one it always was.
    const kept = this.accounts.enabled ? this.storedAccount() : null;
    this.accessToken = '';
    this.refreshToken = '';
    this.env.location.assign(this.url('/logout') +
      (kept && kept.username
        ? '?login_hint=' + encodeURIComponent(kept.username) : ''));
  }

  // ---------------------------------------------------------------------------
  // SWITCHING ACCOUNTS IN THIS TAB (#561, the plan's section 6).
  //
  // The account menu (`WebShell.accountItems()`) offers each other signed-in
  // account of the browser, Sign in with another account and Sign out…, and
  // only with `authn.multipleAccounts` on. A switch is a security-relevant
  // change of context (IR-6), so before the window leaves to sign in:
  //
  //   1. A FORM TYPED IN asks first (`confirmLeave()`), and declining leaves
  //      the page as it is.
  //   2. EVERY REQUEST IN FLIGHT IS ABORTED (`endIdentity()`): the identity
  //      they were sent for has ended, and an answer that arrives anyway is
  //      ABORTED in `sendOnce()` and in `tokenRequest()`, never drawn.
  //   3. EVERY VIEW THIS TAB HOLDS IS DISCARDED (`discardViews()`): the shell,
  //      who it was, the form table, the request schemas, the page, a sign-in
  //      again in progress, the page kept for after a redirect, and the
  //      client's tokens, key and metadata.
  //   4. THE SIGN-IN NAMES THE ACCOUNT (`login_hint`) and the subject the
  //      answer must be for (`expect`), which `finishSignIn()` holds it to.
  //
  // The server decides; none of this is a boundary. `/admin-api` answers from
  // the token's own subject and session, so a tab that kept a view would
  // still be refused anything the new account may not do.
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
    const t = this.t;
    return !!win.confirm(t.has('consoleRuntime.accounts.unsaved')
      ? t.text('consoleRuntime.accounts.unsaved')
      : 'This page has changes that have not been saved. Switch account ' +
        'anyway? They will be lost.');
  }

  /**
   * Discards every view this tab holds for the account it was.
   *
   * @returns nothing
   */
  discardViews(): void {
    const r = this.reauth;
    this.reauth = null;
    if (r) {
      if (r.channel) {
        r.channel.close();
      }
      r.waiting.forEach(function (resolve: Json) {
        resolve(false);
      });
      this.removeReauthBar();
    }
    this.shell = null;
    this.shellPrefix = '';
    this.shellRefusal = null;
    this.me = null;
    this.formTable = null;
    this.spec = null;
    this.view = null;
    this.submitting = null;
    try {
      this.env.sessionStorage.removeItem(RESTORE_KEY);
    } catch (e) {
      // Storage refused: nothing was kept that could be put back.
      this.dirty = false;
    }
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
    const back = this.hereWithFragment();
    this.endIdentity();
    this.discardViews();
    try {
      await this.beginSignIn(back, {
        login_hint: String(account.username || account.sub || ''),
        expect: String(account.sub || '') });
    } catch (e) {
      // THE SIGN-IN COULD NOT BE STARTED (#731): a pushed authorization
      // request the network refused. The views are already gone, so the
      // tab says so rather than staying blank with the rejection unhandled;
      // the account it keeps is still the one it was, so a reload resumes
      // that one, by its hint.
      this.drawProblem('Switching accounts failed',
        'The sign-in as the other account could not be started: ' +
        String((e && e.message) || e) + '. Reload the page to carry on as ' +
        'the account this tab was.');
    }
  }

  /**
   * Signs this tab in as another account: a fresh sign-in (`prompt=login`)
   * with no hint, whose account the tab then is.
   *
   * @returns nothing
   */
  async signInAnother(): Promise<void> {
    if (!this.confirmLeave()) {
      return;
    }
    const back = this.hereWithFragment();
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
      ? doc.getElementById(WebShell.ACCOUNTS_ID) : null;
    if (el) {
      el.innerHTML = ConsoleRuntime.realmLinks(
        WebShell.accountItems(this.accounts, this.subject, this.t),
        this.prefix);
    }
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
    const t = this.t;
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
      // "Copy failed" is a failure, and failures stay English (#539).
      button.textContent = ok
        ? (t.has('consoleRuntime.copied') ? t.text('consoleRuntime.copied')
                                          : 'Copied')
        : 'Copy failed';
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
    // A SIDEBAR SECTION OPENED OR CLOSED (#750): `toggle` does not bubble,
    // so it is caught on the way down.
    this.env.document.addEventListener('toggle', function (event) {
      self.onNavToggle(event && event.target);
    }, true);
    this.env.document.addEventListener('focusin', function (event) {
      self.closeOtherSearches(event && event.target);
    });
    // A FORM TYPED IN (#561): a switch asks before it is lost.
    this.env.document.addEventListener('input', function (event) {
      if (event && event.target && event.target.form) {
        self.dirty = true;
      }
    });
    // THE LANGUAGE CHOOSER (#539 phase 5): a `<select>` with no form, so a
    // change is the event.
    this.env.document.addEventListener('change', function (event) {
      const target = event && event.target;
      if (target && target.id === 'console-language') {
        self.setLanguage(String(target.value || ''));
        return;
      }
      if (target && target.form) {
        self.dirty = true;
      }
    });
    if (this.env.window) {
      // THE EXPLORER'S WAY TO CALL (`admin_api_explorer.js`): this
      // runtime's token and a proof by its key, for a path on this origin.
      this.env.window.stsConsoleFetch = function (method, path, body) {
        return self.send(String(method || 'GET'),
                         self.apiOrigin() + String(path), body);
      };
      this.env.window.addEventListener('hashchange', function () {
        self.markOpenTabs();
      });
      this.env.window.addEventListener('popstate', function () {
        // A FRAGMENT'S OWN NAVIGATION — a tab pressed, or targetFragment() —
        // changes neither the path nor the query, and the browser has
        // already shown its target. Drawing the page again would draw the
        // panel after the navigation and lose `:target`: the tab would flash
        // and fall back to the first.
        if (self.env.location.pathname + self.env.location.search ===
            self.drawnAt) {
          self.markOpenTabs();
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
