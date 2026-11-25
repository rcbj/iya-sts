// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1

'use strict';
//
// File: web_spa_client.ts
//
// ---------------------------------------------------------------------------
// WHAT THE TWO STATIC APPLICATIONS SHARE AS OAUTH CLIENTS (#568).
//
// The admin console (#446) and the user portal (#568) are both static
// applications in the browser and both PUBLIC clients of this service's own
// authorization server: the authorization code flow with PKCE (S256), and
// every token bound by DPoP (RFC 9449) to a P-256 key the page makes
// NON-EXTRACTABLE — the condition rcbj attached to a public console, and to a
// public portal on #568. This class is that half, moved out of
// `ConsoleRuntime` verbatim when the portal became the second of them, so the
// two cannot drift into two readings of one RFC:
//
//   * the key and the proof (`ensureKey()`, `proof()`), a server's
//     `DPoP-Nonce` kept for the next proof (`keepNonce()`);
//   * the token endpoint (`tokenRequest()`), retried once on
//     `use_dpop_nonce`, and what it answered kept in memory only
//     (`keepTokens()`) — a reload signs in again, silently while the sign-on
//     session lasts;
//   * the authorization request (`authorizationRequestUrl()`), pushed first
//     where the realm requires it, and a JARM answer opened and checked
//     (`openAuthorizationResponse()`).
//   * A CALLBACK THIS TAB DID NOT START (`handCallbackToStarter()`). A
//     same-device wallet comes back in another tab. That tab offers the
//     authorization response to the tab that still holds the PKCE record.
//   * ONE ACCOUNT PER TAB (#561, with `authn.multipleAccounts` on): the
//     tab's account `{ sub, username }` in sessionStorage
//     (`storedAccount()`), sent as `login_hint` on every sign-in the
//     runtime starts; the IDENTITY every request belongs to
//     (`identitySignal()`, `endIdentity()`), so a switch aborts what is in
//     flight and an answer that arrives anyway is not believed; and the one
//     subject check both runtimes make of an answer (`answerIsFor()`).
//
// What each application does with a page — routing, drawing, its forms —
// stays in its own runtime (`admin-ui/web_runtime.ts`,
// `portal/web_portal_runtime.ts`).
//
// IN `common/` SINCE #570 (it was `admin-ui/web_spa_client.ts`), with what a
// runtime needs whether or not it is a client — the address of a path, the
// query, fetch, forms, links — moved under it into `web_page.ts`, which the
// public surfaces of #569 stand on directly: they hold no token. Nothing in
// this class changed in the move; in particular the push still carries no
// DPoP proof and a JARM answer is still opened before anything in it is
// believed (both argued where they are below).
//
// A `web_` MODULE, on `admin-ui/web_kit.ts`'s terms: it requires `web_page.ts`
// and nothing else, logs nothing, and is bundled for a browser by
// `build-typescript.sh`. Everything it touches in the browser arrives in
// `env`, so a test drives it in node.
// ---------------------------------------------------------------------------

import WebPage = require('./web_page');
import WebAccounts = require('./web_accounts');
import WebI18n = require('./web_i18n');
import WebMessages = require('./web_messages');
import WebSafeDom = require('./web_safe_dom');
import WebDocLinks = require('./web_doc_links');

type Json = any;

/**
 * What a static application's client is: its id, what it asks for and where
 * its own pages and API are.
 */
interface SpaClientOptions {
  // The registered public client.
  clientId: string;
  // The scope the authorization request asks for.
  scope: string;
  // The `data-sts-*` attributes of the shell's html element, by the first
  // path segment each stands for: `{ '/oauth2': 'data-sts-oauth', ... }`.
  elsewhere: Record<string, string>;
  // The sessionStorage key the tab's account is kept under (#561):
  // `sts-console-account`, `sts-portal-account`.
  accountKey?: string;
  // THE SCOPES A SECOND AUTHORIZATION MAY ADD (#2168): what a write may
  // need beyond the read scope the application signs in with. A challenge
  // naming anything else starts no step.
  writeScopes?: string[];
  // Those of them that are asked for with a fresh sign-in (`prompt=login`,
  // `max_age=0`), never silently: `admin:security`.
  freshScopes?: string[];
}

/**
 * One write token (#2168): the access token a second authorization gave for
 * one resource, when it stops being used, and the scopes it carries.
 */
interface WriteGrant {
  token: string;
  expiresAt: number;
  scopes: string[];
}

/**
 * A static application's OAuth 2.0 client: PKCE, DPoP and the tokens.
 */
class SpaClient extends WebPage {
  // THE CHANNEL A CALLBACK OFFERS ITSELF ON when this tab holds no matching
  // PKCE record, and the sessionStorage keys the tab that started the
  // sign-in wrote. `oid4vc/web_vc_signin.ts` listens under these same names.
  static readonly CALLBACK_CHANNEL = 'sts-spa-callback';
  static readonly SIGNIN_KEYS: string[] = ['sts-portal-signin',
                                            'sts-console-signin'];
  // How long the callback waits for the tab that holds the record, in
  // milliseconds. One answer, not a poll.
  static readonly CALLBACK_HANDOFF_MS = 1000;
  protected clientId: string;
  protected scope: string;
  protected accessToken: string;
  protected refreshToken: string;
  protected expiresAt: number;
  protected key: Json;
  protected publicJwk: Json;
  protected nonce: string;
  // WHO SIGNED IN (#508): the ID Token's `sub`.
  protected subject: string;
  // Where the authorization server, the API and the sign-in service are when
  // they are not on this application's own listener (#472) is `WebPage`'s
  // `elsewhere`, read from the shell's `data-sts-*` attributes.
  // The realm's authorization server metadata, read once (`asMetadata()`).
  protected metadata: Json;
  // THE TAB'S ACCOUNT (#561): where it is kept, the browser's account list
  // as last read (`WebAccounts.off()` until it is), and the channel a change
  // to the list is heard on.
  protected accountKey: string;
  protected accounts: Json;
  protected accountChannel: Json;
  // THE IDENTITY EVERY REQUEST IS SENT FOR (#561): a number that a switch
  // moves on, and the abort controller of the requests sent under it. A
  // request remembers the number it was sent under, and an answer that
  // comes back under another is not believed, whether or not the browser
  // could abort it.
  protected identity: number;
  protected identityController: Json;
  // THE WRITE TOKENS (#2168), by the resource each is audienced to, and the
  // scopes a step may add and those it asks with a fresh sign-in.
  protected writeGrants: Record<string, WriteGrant>;
  protected writeScopes: string[];
  protected freshScopes: string[];
  // The step in progress (#2168), so two writes pressed together share one
  // second authorization; null when none is.
  protected stepping: Json;
  // THE REALM WHOSE AUTHORIZATION SERVER ISSUED THE TOKENS IN HAND (#1038,
  // #2200): its prefix, null until a runtime records one. A runtime whose
  // realm switcher keeps the token while the page moves to another realm
  // (the console's, the reports application's) goes on asking THIS realm
  // for every token — a refresh, a second authorization (#2168) — while
  // the pages and the API calls name the realm on screen.
  protected issuerPrefix: string | null;

  /**
   * Makes the client.
   *
   * @param env - the browser's objects: `fetch`, `crypto` (WebCrypto),
   *   `location`, `history`, `document`, `sessionStorage`, `navigator`,
   *   `window`, and, for a test, `now` (milliseconds; `Date.now` where left
   *   out)
   * @param prefix - the realm's path prefix, '' in the default realm
   * @param options - the client's id, its scope and the shell's attributes
   */
  constructor(env: Json, prefix: string, options: SpaClientOptions) {
    super(env, prefix, options.elsewhere);
    this.clientId = options.clientId;
    this.scope = options.scope;
    this.accessToken = '';
    this.refreshToken = '';
    this.expiresAt = 0;
    this.key = null;
    this.publicJwk = null;
    this.nonce = '';
    this.subject = '';
    this.metadata = null;
    this.accountKey = options.accountKey || '';
    this.accounts = WebAccounts.off();
    this.accountChannel = null;
    this.identity = 0;
    this.identityController = null;
    this.writeGrants = {};
    this.writeScopes = (options.writeScopes || []).slice(0);
    this.freshScopes = (options.freshScopes || []).slice(0);
    this.stepping = null;
    this.issuerPrefix = null;
  }

  // ---------------------------------------------------------------------------
  // ONE ACCOUNT PER TAB (#561, the plan's section 6).
  //
  // EVERYTHING HERE IS INERT WITH `authn.multipleAccounts` OFF: nothing is
  // stored unless the list said `enabled`, and a sign-in sends a hint only
  // where something is stored — so a browser that never saw the setting on
  // sends the requests it always sent.
  //
  // WHAT IS STORED is `{ sub, username }` and nothing else — no token, no
  // sid, no key — in sessionStorage, which is the TAB's: a new tab has
  // nothing (and so no hint: the server signs it in silently with one live
  // account and shows the picker with more, decision 3), and a duplicated or
  // restored tab has its own copy (and resumes that account, checked by the
  // server at the authorization request, decision 4).
  // ---------------------------------------------------------------------------
  /**
   * The tab's account, where one is kept.
   *
   * @returns `{ sub, username }`, or null
   */
  storedAccount(): Json {
    if (!this.accountKey || !this.env.sessionStorage) {
      return null;
    }
    try {
      const saved = JSON.parse(this.env.sessionStorage.getItem(
        this.accountKey) || 'null');
      return saved && (saved.sub || saved.username)
        ? { sub: String(saved.sub || ''),
            username: String(saved.username || '') } : null;
    } catch (e) {
      // Not JSON: no account kept, so no hint — a new tab's behaviour.
      return null;
    }
  }

  /**
   * Keeps the tab's account, or forgets it.
   *
   * @param account - `{ sub, username }`, or null to forget it
   * @returns nothing
   */
  keepAccount(account: Json): void {
    if (!this.accountKey || !this.env.sessionStorage) {
      return;
    }
    try {
      if (!account || !(account.sub || account.username)) {
        this.env.sessionStorage.removeItem(this.accountKey);
        return;
      }
      this.env.sessionStorage.setItem(this.accountKey, JSON.stringify({
        sub: String(account.sub || ''),
        username: String(account.username || '') }));
    } catch (e) {
      // STORAGE REFUSED: the tab signs in without a hint next time, which is
      // a new tab's behaviour and never another account's.
      return;
    }
  }

  /**
   * The `login_hint` a sign-in sends: what the caller names, else the tab's
   * account, else none.
   *
   * @param extra - what the sign-in was started with: `login_hint` ('' for
   *   none at all, as Sign in with another account asks)
   * @returns the hint, or ''
   */
  hintFor(extra: Json): string {
    if (extra && typeof extra.login_hint === 'string') {
      return extra.login_hint;
    }
    const kept = this.storedAccount();
    return kept ? String(kept.username || kept.sub || '') : '';
  }

  /**
   * Reads the browser's account list, keeps it, and keeps the tab's account
   * from it: the signed-in subject's username, or forgets the account where
   * the list is off.
   *
   * @param username - the signed-in person's username as the application
   *   knows it, for a subject the list does not name
   * @returns the list
   */
  async readAccounts(username: string): Promise<Json> {
    const list = await WebAccounts.fetchList(this.env, this.prefix);
    this.accounts = list;
    if (!list.enabled) {
      // OFF: nothing kept, so the next sign-in is today's.
      this.keepAccount(null);
      return list;
    }
    if (this.subject) {
      const found = WebAccounts.bySubject(list, this.subject);
      this.keepAccount({ sub: this.subject,
                         username: found ? String(found.username || '')
                                         : String(username || '') });
    }
    return list;
  }

  /**
   * Whether an answer is for the subject asked for: the one subject check
   * the console's popup made first (#508) and every switch makes now
   * (#561).
   *
   * @param expected - the subject asked for
   * @param idToken - the ID Token the token endpoint answered
   * @returns whether its `sub` is that subject
   */
  static answerIsFor(expected: string, idToken: Json): boolean {
    const got = SpaClient.subjectOf(idToken);
    return !!expected && !!got && expected === got;
  }

  /**
   * The abort signal of the identity requests are being sent for now.
   *
   * @returns the signal, or undefined where the browser has no
   *   AbortController
   */
  identitySignal(): Json {
    if (!this.identityController) {
      const win = this.env.window;
      const AC = (win && win.AbortController) ||
        (typeof AbortController === 'function' ? AbortController : null);
      if (!AC) {
        return undefined;
      }
      this.identityController = new AC();
    }
    return this.identityController.signal;
  }

  /**
   * Ends the identity requests are sent for: every request in flight is
   * aborted, and an answer to one sent before is not believed.
   *
   * @returns nothing
   */
  endIdentity(): void {
    this.identity++;
    const controller = this.identityController;
    this.identityController = null;
    if (controller) {
      controller.abort();
    }
  }

  /**
   * Discards what this client holds for the identity that just ended: the
   * tokens, the subject, the DPoP key and its nonce, and the metadata. A
   * key is made again for the next sign-in, as a page load makes one.
   *
   * @returns nothing
   */
  discardClient(): void {
    this.accessToken = '';
    this.refreshToken = '';
    this.expiresAt = 0;
    this.subject = '';
    this.key = null;
    this.publicJwk = null;
    this.nonce = '';
    this.metadata = null;
    this.writeGrants = {};
  }

  /**
   * Listens for changes to the browser's account list, once: each change
   * reads the list again and hands it to `then`, and changes nothing else.
   *
   * @param then - draws the menu again from the list
   * @returns nothing
   */
  listenForAccounts(then: (list: Json) => void): void {
    if (this.accountChannel || !this.accounts.enabled) {
      return;
    }
    const self = this;
    this.accountChannel = WebAccounts.openChannel(this.env, function () {
      WebAccounts.fetchList(self.env, self.prefix).then(function (list) {
        // A READ THAT ANSWERS OFF KEEPS THE LIST IN HAND (#731).
        // `fetchList()` answers off for a network failure as well as for
        // the setting turned off, and taking it here turned a tab's list
        // off on one dropped request: its menu emptied and its sign-out
        // stopped naming its account. The static surfaces' control already
        // kept its list (`WebSurface.refreshAccounts()`); the setting
        // turned off reaches this tab at its next page load, whose shell
        // says so.
        if (!list.enabled) {
          return self.accounts;
        }
        // A LIST READ ON A MESSAGE IS NEVER ANNOUNCED: only a change this
        // tab made is (`WebAccounts`).
        self.accounts = list;
        then(list);
        return list;
      }, function () {
        // `fetchList()` catches its own failures; nothing reaches here.
        return null;
      });
    });
  }

  /**
   * Announces that this tab changed the browser's account list.
   *
   * @param change - `added`, `signed-out`, `forgotten` or `changed`
   * @returns nothing
   */
  announceAccounts(change: string): void {
    if (!this.accounts.enabled) {
      return;
    }
    const channel = this.accountChannel ||
      WebAccounts.openChannel(this.env, function () {
        return undefined;
      });
    channel.post(change);
    if (!this.accountChannel) {
      channel.close();
    }
  }

  // `SpaClient.queryOf()` is `WebPage.queryOf()`, inherited.

  // --- encoding and crypto -------------------------------------------------

  // ---------------------------------------------------------------------------
  // WEBCRYPTO IS ASKED FOR BEFORE ANYTHING ELSE (#2143, ASVS 5.0.0 3.7.5).
  //
  // Every sign-in this class makes needs it: the PKCE verifier and the DPoP
  // `jti` are `getRandomValues()`, the challenge and `ath` are `digest()`,
  // the key is `generateKey()` and `exportKey()`, every proof is `sign()`,
  // and a JARM answer is `importKey()` and `verify()`. A browser holds
  // `crypto.subtle` only in a SECURE CONTEXT, so a page reached over plain
  // HTTP (or in a browser too old to have it) used to fail at the first
  // `generateKey()` with an unhandled rejection and a blank page. Each
  // runtime asks `webCryptoMissing()` before it wires or draws anything, and
  // where it answers true draws one sentence, in the page's language, from
  // `noWebCryptoWords()` — and starts no sign-in, because one could not be
  // finished.
  // ---------------------------------------------------------------------------
  /**
   * The WebCrypto calls a sign-in makes, each a method of `crypto.subtle`.
   */
  static readonly WEBCRYPTO_CALLS: string[] = ['digest', 'generateKey',
    'exportKey', 'importKey', 'sign', 'verify'];

  /**
   * Whether this browser lacks what a sign-in needs from WebCrypto.
   *
   * @param env - the browser's objects; `env.crypto` is asked
   * @returns true when `crypto`, `crypto.getRandomValues` or any of
   *   `WEBCRYPTO_CALLS` on `crypto.subtle` is missing
   */
  static webCryptoMissing(env: Json): boolean {
    const c = env ? env.crypto : null;
    if (!c || typeof c.getRandomValues !== 'function' || !c.subtle) {
      return true;
    }
    return SpaClient.WEBCRYPTO_CALLS.some(function (name) {
      return typeof c.subtle[name] !== 'function';
    });
  }

  /**
   * The words a page without WebCrypto draws, in the page's language: the
   * namespace's `noWebCrypto.title` and `noWebCrypto.text`, and the
   * translator they came from (with the footer's words in it).
   *
   * @param namespace - the surface's catalog namespace (`consoleRuntime`,
   *   `portal`, `report`)
   * @returns `{ t, title, text }`
   */
  async noWebCryptoWords(namespace: string): Promise<Json> {
    const t = await this.problemTranslator(namespace);
    const said = function (key: string, english: string): string {
      const full = namespace + '.' + key;
      return t.has(full) ? t.text(full) : english;
    };
    return {
      t: t,
      title: said('noWebCrypto.title', 'This browser cannot open this page'),
      text: said('noWebCrypto.text', 'This browser cannot run this page ' +
        'securely: WebCrypto is unavailable, usually because the page was ' +
        'not opened over HTTPS or the browser is too old.')
    };
  }

  /**
   * The translator a page drawn before sign-in says a problem with: the
   * namespace's catalogs (and, with every `WebI18n`, the `browser` one), or
   * none where no catalog can be had, so the English is drawn.
   *
   * @param namespace - the surface's catalog namespace
   * @returns the translator
   */
  async problemTranslator(namespace: string): Promise<Json> {
    let t: Json = null;
    try {
      t = await new WebI18n(this.env, this, [namespace]).load();
    } catch (e) {
      // No catalog to be had: the English is drawn instead.
      t = WebMessages.WebTranslator.fromData(null);
    }
    return t;
  }

  // ---------------------------------------------------------------------------
  // SESSION STORAGE IS ASKED FOR TOO, BESIDE WEBCRYPTO (#2220, ASVS 5.0.0
  // 3.1.1). A sign-in keeps its PKCE verifier, its `state` and where it
  // began in `sessionStorage` until the browser comes back from
  // `/oauth2/authorize`. A browser that blocks it — private browsing, site
  // data refused — threw at `setItem()` (or, in some, at the bare
  // `window.sessionStorage`), and the sign-in never finished, with nothing
  // said. Each entry hands its runtime `storageOf()`, which never throws, and
  // each runtime asks `sessionStorageMissing()` before anything, beside
  // `webCryptoMissing()`, and draws `noStorageWords()` in its place.
  // ---------------------------------------------------------------------------
  /**
   * The key a write is tried under, and removed at once.
   */
  static readonly STORAGE_PROBE = 'sts-storage-probe';

  /**
   * The window's `sessionStorage`, or null where reading it throws (a
   * browser that blocks site data refuses the property itself).
   *
   * @param w - the window
   * @returns the storage, or null
   */
  static storageOf(w: Json): Json {
    try {
      return (w && w.sessionStorage) || null;
    } catch (e) {
      // Refused: the runtime says so at start (`sessionStorageMissing()`).
      return null;
    }
  }

  /**
   * Whether this browser lacks the `sessionStorage` a sign-in needs: there
   * is none, or a write to it throws.
   *
   * @param env - the browser's objects; `env.sessionStorage` is asked
   * @returns true when a sign-in could not keep its record
   */
  static sessionStorageMissing(env: Json): boolean {
    const store = env ? env.sessionStorage : null;
    if (!store || typeof store.setItem !== 'function' ||
        typeof store.getItem !== 'function' ||
        typeof store.removeItem !== 'function') {
      return true;
    }
    try {
      store.setItem(SpaClient.STORAGE_PROBE, '1');
      const read = store.getItem(SpaClient.STORAGE_PROBE);
      store.removeItem(SpaClient.STORAGE_PROBE);
      return read !== '1';
    } catch (e) {
      // A quota of nothing, or storage refused: the same for a sign-in.
      return true;
    }
  }

  /**
   * The words a page without session storage draws, in the page's
   * language: `browser.noStorage.title` and `browser.noStorage.text`, and
   * the translator they came from.
   *
   * @param namespace - the surface's catalog namespace
   * @returns `{ t, title, text }`
   */
  async noStorageWords(namespace: string): Promise<Json> {
    const t = await this.problemTranslator(namespace);
    return {
      t: t,
      title: t.has('browser.noStorage.title')
        ? t.text('browser.noStorage.title')
        : 'This browser cannot sign you in here',
      text: t.has('browser.noStorage.text')
        ? t.text('browser.noStorage.text')
        : 'This browser does not let this page use session storage, which ' +
          'signing in needs. Private browsing and some privacy settings ' +
          'block it: allow site data for this site, then reload the page.'
    };
  }

  /**
   * The link to what this service needs from a browser (#2220), as a
   * paragraph, in the page's language: what each "this browser cannot"
   * page carries.
   *
   * @param t - the page's translator, or null
   * @returns the markup
   */
  static browserSupportHtml(t: Json): string {
    const label = t && t.has && t.has('browser.requirements')
      ? t.html('browser.requirements')
      : 'What this service needs from a browser';
    return '<p class="sts-browser-support"><a href="' +
      WebDocLinks.esc(WebDocLinks.browserSupport()) +
      '" rel="noopener noreferrer">' + label + '</a></p>';
  }


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
    return SpaClient.b64u(bytes);
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
    return SpaClient.b64u(new Uint8Array(digest));
  }

  // THE OPENID CONNECT `nonce` (Core section 3.1.2.1), which FAPI 1.0
  // requires on every request asking for `openid` and the console and portal
  // always do. It is DERIVED from the sign-in's PKCE verifier rather than
  // kept beside it: the verifier already crosses the redirect (and a
  // popup's sign-in) in what each runtime saves, so the nonce needs no
  // storage of its own and cannot be lost apart from it. The verifier is
  // never sent; this hash of it, under its own label so it is not the code
  // challenge, is. The ID Token the token endpoint answers this page with is
  // then held to it (`nonceMatches()`).
  /**
   * The `nonce` of a sign-in whose PKCE verifier this is.
   *
   * @param verifier - the sign-in's PKCE verifier
   * @returns the nonce, base64url
   */
  async nonceFor(verifier: string): Promise<string> {
    return this.sha256('nonce:' + verifier);
  }

  // READ, NOT VERIFIED, for `subjectOf()`'s reason: the ID Token came to
  // this page straight from the token endpoint over TLS, which is what
  // OpenID Connect Core section 3.1.3.7 accepts in place of the signature
  // for the code flow, and the nonce is compared with what this page itself
  // asked for.
  /**
   * Whether an ID Token carries the nonce of the sign-in that verifier
   * began.
   *
   * @param idToken - the compact JWT the token endpoint answered
   * @param verifier - the sign-in's PKCE verifier
   * @returns whether the nonce is there and is that sign-in's
   */
  async nonceMatches(idToken: Json, verifier: string): Promise<boolean> {
    const carried = SpaClient.claimOf(idToken, 'nonce');
    if (carried === '' || carried !== await this.nonceFor(verifier)) {
      return false;
    }
    // ASVS 5.0.0 10.5.4 and 6.8.2: the token is for this client, from this
    // server. `iss` is held to the metadata where this page has read it, and
    // that has passed its own check in `asMetadata()`.
    const issuer = String((this.metadata && this.metadata.issuer) || '');
    return SpaClient.claimOf(idToken, 'aud').split(',')
      .indexOf(this.clientId) >= 0 &&
      (!issuer || SpaClient.claimOf(idToken, 'iss') === issuer);
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
      return SpaClient.b64u(new TextEncoder().encode(JSON.stringify(obj)));
    };
    const input = enc(header) + '.' + enc(claims);
    const signature = await this.env.crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' }, this.key.privateKey,
      new TextEncoder().encode(input));
    return input + '.' + SpaClient.b64u(new Uint8Array(signature));
  }

  // --- the authorization server --------------------------------------------
  // (This realm's address for a path, `url()`, is `WebPage`'s.)

  /**
   * The address of a path at the realm that issued the tokens in hand
   * (`issuerPrefix`, #2200): the authorization server's endpoints, the
   * callback a token is redeemed at, and the resource a token is for. The
   * realm on screen's where none was recorded, or it is that realm.
   *
   * @param path - `/oauth2/token`, `/admin/callback`, `/admin-api`
   * @returns the absolute URL
   */
  issuerUrl(path: string): string {
    if (this.issuerPrefix === null || this.issuerPrefix === this.prefix) {
      return this.url(path);
    }
    // `url()` is a runtime's (the reports application's reads its own
    // fields), so it is asked with the issuer's prefix in place, and the
    // prefix put back before anything else can run.
    const here = this.prefix;
    this.prefix = this.issuerPrefix;
    try {
      return this.url(path);
    } finally {
      this.prefix = here;
    }
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
    const endpoint = this.issuerUrl('/oauth2/token');
    // THE IDENTITY IT IS SENT FOR (#561): a switch aborts it, and an answer
    // that comes back after one is not kept.
    const identity = this.identity;
    const aborted = { status: 0, aborted: true,
                      json: { error: 'aborted' } };
    for (let attempt = 0; attempt < 2; attempt++) {
      let res: Json = null;
      try {
        res = await this.env.fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                     'DPoP': await this.proof('POST', endpoint, '') },
          body: new URLSearchParams(form).toString(),
          signal: this.identitySignal()
        });
      } catch (e) {
        if (identity !== this.identity) {
          return aborted;
        }
        throw e;
      }
      if (identity !== this.identity) {
        return aborted;
      }
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

  // ---------------------------------------------------------------------------
  // PUSHED AUTHORIZATION REQUESTS (RFC 9126), WHERE THE REALM REQUIRES THEM
  // (#568). FAPI 2.0 makes PAR the only way to send an authorization request,
  // and a realm may require it on its own (`oauth2.requirePar`). The server-
  // rendered surfaces pushed through `oidc_rp.ts`; a static one pushes from
  // the browser: its parameters POSTed to the PAR endpoint the metadata names
  // — a public client authenticates with nothing, as section 2 allows — and
  // the browser sent to the authorization endpoint with the
  // `request_uri` it answered and the client id alone. Where the metadata
  // requires nothing, the request is the ordinary query, as it always was.
  // ---------------------------------------------------------------------------
  /**
   * The authorization server's metadata for this realm (RFC 8414), once.
   *
   * @returns the metadata, or {} where it cannot be read
   */
  async asMetadata(): Promise<Json> {
    if (this.metadata) {
      return this.metadata;
    }
    let json: Json = {};
    try {
      const res = await this.env.fetch(
        this.issuerUrl('/.well-known/oauth-authorization-server'),
        { headers: { 'Accept': 'application/json' } });
      json = res.status === 200 ? await res.json() : {};
    } catch (e) {
      // No metadata: the ordinary request, which a realm that requires PAR
      // refuses in words the page draws.
      json = {};
    }
    // RFC 8414 section 3.3 (ASVS 5.0.0 10.5.3): the document must name the
    // server it was fetched from. One that does not is ignored, as if none had
    // answered.
    const meta = json || {};
    const expected = String(this.issuerUrl('')).replace(/\/+$/, '');
    this.metadata = meta.issuer && String(meta.issuer) !== expected ? {} : meta;
    return this.metadata;
  }

  /**
   * RFC 9207's `iss` on the authorization response, where the server sends one
   * (ASVS 5.0.0 10.2.2): it must name this server.
   *
   * @param query - the response's parameters
   * @returns false when the response came from somebody else
   */
  async issuerMatches(query: Json): Promise<boolean> {
    const sent = String((query && query.iss) || '');
    if (!sent) {
      return true;
    }
    const meta = await this.asMetadata();
    return !meta.issuer || sent === String(meta.issuer);
  }

  /**
   * The authorization request's URL: pushed first where the realm requires
   * it, the query otherwise.
   *
   * @param params - the request's parameters, `client_id` among them
   * @returns the URL to send the browser to
   */
  async authorizationRequestUrl(params: Json): Promise<string> {
    const authorize = this.issuerUrl('/oauth2/authorize');
    const meta = await this.asMetadata();
    // JARM WHERE THE REALM OFFERS NOTHING ELSE (FAPI 2.0 Message Signing,
    // which leaves only the JWT-secured modes in `response_modes_supported`):
    // the answer comes back as a signed `response`, which
    // `openAuthorizationResponse()` verifies.
    const modes = meta.response_modes_supported;
    if (Array.isArray(modes) && modes.indexOf('query') < 0 &&
        (modes.indexOf('jwt') >= 0 || modes.indexOf('query.jwt') >= 0)) {
      params.response_mode = modes.indexOf('jwt') >= 0 ? 'jwt' : 'query.jwt';
    }
    // THE CODE COMES BACK IN THE FRAGMENT (#1454, ASVS 5.0.0 14.2.1), which a
    // browser does not send to any server. A static application has no route
    // that could read a `form_post` body.
    if (!params.response_mode && Array.isArray(modes) &&
        modes.indexOf('fragment') >= 0) {
      params.response_mode = 'fragment';
    }
    if (meta.require_pushed_authorization_requests !== true) {
      return authorize + '?' + SpaClient.formOf(params);
    }
    const endpoint = String(meta.pushed_authorization_request_endpoint ||
                            this.issuerUrl('/oauth2/par'));
    // NO DPoP PROOF ON THE PUSH: a proof there binds the authorization code
    // to its key (RFC 9449 section 10), and the key is this page load's —
    // the callback is another page load, with another key that cannot
    // redeem it. The tokens are bound where they are issued, at the token
    // request, by the key that will use them.
    const res = await this.env.fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: SpaClient.formOf(params) });
    const json = await res.json().catch(function () {
      return {};
    });
    if (res.status === 201 && json.request_uri) {
      return authorize + '?' + new URLSearchParams({
        client_id: String(params.client_id || this.clientId),
        request_uri: String(json.request_uri) }).toString();
    }
    // A REFUSED PUSH: the ordinary request, which the authorization endpoint
    // then refuses with the reason, drawn where the person can read it.
    return authorize + '?' + SpaClient.formOf(params);
  }

  /**
   * Form-encodes parameters, a value that is an array as the parameter
   * repeated — RFC 8707's `resource`, which a client asking for two
   * resources sends twice (#607). `URLSearchParams(object)` would join the
   * array with commas into one value naming no resource.
   *
   * @param params - the parameters
   * @returns the encoded form
   */
  static formOf(params: Json): string {
    const form = new URLSearchParams();
    Object.keys(params || {}).forEach(function (name) {
      [].concat(params[name]).forEach(function (one) {
        form.append(name, String(one));
      });
    });
    return form.toString();
  }

  // ---------------------------------------------------------------------------
  // A JWT-SECURED AUTHORIZATION RESPONSE (JARM, #568), OPENED AND CHECKED
  // BEFORE ANYTHING IN IT IS BELIEVED: the signature against the realm's
  // published key (by `kid`, verified with WebCrypto), `iss` the realm's
  // issuer, `aud` this client, `exp` in the future — JARM section 2.4. Only
  // then are its `code`, `state` and `error` handed back, in the shape an
  // ordinary callback's query has. An answer that is not a JWT is that query.
  // ---------------------------------------------------------------------------
  /**
   * Bytes of a base64url string.
   *
   * @param text - the encoding
   * @returns the bytes
   */
  static fromB64u(text: string): Uint8Array {
    let t = String(text || '').replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) {
      t += '=';
    }
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }

  /**
   * WebCrypto's names for a JWS algorithm: how its key is imported and how
   * a signature is verified, or null for one WebCrypto does not do.
   *
   * @param alg - the JWS `alg`
   * @returns `{ importAs, verifyAs }`, or null
   */
  static webCryptoAlg(alg: string): Json {
    const ec = function (curve: string, hash: string): Json {
      return { importAs: { name: 'ECDSA', namedCurve: curve },
               verifyAs: { name: 'ECDSA', hash: hash } };
    };
    const pss = function (hash: string, salt: number): Json {
      return { importAs: { name: 'RSA-PSS', hash: hash },
               verifyAs: { name: 'RSA-PSS', saltLength: salt } };
    };
    const rsa = function (hash: string): Json {
      return { importAs: { name: 'RSASSA-PKCS1-v1_5', hash: hash },
               verifyAs: { name: 'RSASSA-PKCS1-v1_5' } };
    };
    const table: Json = {
      ES256: ec('P-256', 'SHA-256'), ES384: ec('P-384', 'SHA-384'),
      ES512: ec('P-521', 'SHA-512'),
      PS256: pss('SHA-256', 32), PS384: pss('SHA-384', 48),
      PS512: pss('SHA-512', 64),
      RS256: rsa('SHA-256'), RS384: rsa('SHA-384'), RS512: rsa('SHA-512'),
      EdDSA: { importAs: { name: 'Ed25519' }, verifyAs: { name: 'Ed25519' } },
      Ed25519: { importAs: { name: 'Ed25519' },
                 verifyAs: { name: 'Ed25519' } }
    };
    return table[alg] || null;
  }

  /**
   * The authorization response a callback carries: a JARM `response`
   * opened and checked, or the query itself.
   *
   * @param query - the callback's query
   * @returns `{ code, state, error, error_description, iss }`
   */
  /**
   * The parameters of the authorization response this page was loaded with,
   * from the fragment or, for a realm that offers only the query, the query.
   *
   * @returns the parameters
   */
  callbackParameters(): Json {
    const hash = String(this.env.location.hash || '').replace(/^#/, '');
    return /(^|&)(code|error|response)=/.test(hash)
      ? SpaClient.queryOf('?' + hash)
      : SpaClient.queryOf(this.env.location.search);
  }

  async openAuthorizationResponse(query: Json): Promise<Json> {
    if (!query || !query.response) {
      return query || {};
    }
    const refused = function (why: string): Json {
      return { error: 'invalid_response', state: '',
               error_description: 'The authorization response could not ' +
                 'be trusted: ' + why + '.' };
    };
    const parts = String(query.response).split('.');
    if (parts.length !== 3) {
      return refused('it is not a signed JWT');
    }
    let header: Json = null;
    let claims: Json = null;
    try {
      header = JSON.parse(new TextDecoder().decode(
        SpaClient.fromB64u(parts[0])));
      claims = JSON.parse(new TextDecoder().decode(
        SpaClient.fromB64u(parts[1])));
    } catch (e) {
      return refused('its header or claims are not JSON');
    }
    const how = SpaClient.webCryptoAlg(String(header.alg || ''));
    if (!how) {
      return refused('its algorithm ' + JSON.stringify(header.alg) +
                     ' is not one this browser can verify');
    }
    const meta = await this.asMetadata();
    let keys: Json[] = [];
    try {
      const res = await this.env.fetch(String(meta.jwks_uri ||
        this.issuerUrl('/oauth2/jwks')),
        { headers: { 'Accept': 'application/json' } });
      keys = ((await res.json()) || {}).keys || [];
    } catch (e) {
      return refused('the realm\'s keys could not be read');
    }
    const jwk = keys.filter(function (one: Json): boolean {
      return !header.kid || one.kid === header.kid;
    })[0];
    if (!jwk) {
      return refused('no published key has its kid');
    }
    const material: Json = { kty: jwk.kty };
    ['crv', 'x', 'y', 'n', 'e'].forEach(function (name) {
      if (jwk[name] !== undefined) {
        material[name] = jwk[name];
      }
    });
    let valid = false;
    try {
      const key = await this.env.crypto.subtle.importKey('jwk', material,
        how.importAs, false, ['verify']);
      valid = await this.env.crypto.subtle.verify(how.verifyAs, key,
        SpaClient.fromB64u(parts[2]),
        new TextEncoder().encode(parts[0] + '.' + parts[1]));
    } catch (e) {
      valid = false;
    }
    if (!valid) {
      return refused('its signature does not verify');
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const now = Math.floor((this.env.now ? this.env.now() : Date.now()) /
                           1000);
    if (meta.issuer && claims.iss !== meta.issuer) {
      return refused('it names another issuer');
    }
    if (audiences.indexOf(this.clientId) < 0) {
      return refused('it is for another client');
    }
    if (!claims.exp || Number(claims.exp) <= now) {
      return refused('it has expired');
    }
    return { code: claims.code, state: claims.state, error: claims.error,
             error_description: claims.error_description, iss: claims.iss };
  }

  /**
   * Offers this callback to the tab that started the sign-in.
   *
   * A same-device wallet opens the verifier's return in a new tab. The
   * passkey, when one is asked for, finishes there, and the authorization
   * server then sends that tab to this callback. The PKCE record was written
   * in the tab that called `beginSignIn` and never left it, so this tab
   * cannot redeem the code. It asks that tab to load this address. The code
   * rides only on the answer to a tab that said it holds the record. No
   * answer within a second, and this tab finishes the refusal itself.
   *
   * @param query - the opened authorization response
   * @returns whether a tab accepted the callback
   */
  handCallbackToStarter(query: Json): Promise<boolean> {
    const win = this.env.window;
    const BC = win && win.BroadcastChannel;
    const state = String((query && query.state) || '');
    const code = String((query && query.code) || '');
    if (!state || !code || typeof BC !== 'function' || !win.setTimeout) {
      return Promise.resolve(false);
    }
    const self = this;
    return new Promise(function (resolve) {
      const channel = new BC(SpaClient.CALLBACK_CHANNEL);
      const nonce = self.random(16);
      let settled = false;
      let timer: Json = null;
      const finish = function (ok: boolean): void {
        if (settled) {
          return;
        }
        settled = true;
        if (timer !== null && win.clearTimeout) {
          win.clearTimeout(timer);
        }
        channel.close();
        resolve(ok);
      };
      // ONE WAIT, for a tab that is already open. Nothing re-arms it.
      timer = win.setTimeout(function () {
        finish(false);
      }, SpaClient.CALLBACK_HANDOFF_MS);
      channel.onmessage = function (event: Json) {
        const data = event && event.data;
        if (!data || data.type !== 'ack' || data.nonce !== nonce ||
            data.state !== state) {
          return;
        }
        const loc = self.env.location;
        channel.postMessage({
          type: 'go', state: state, nonce: nonce,
          location: String(loc.pathname || '') + String(loc.search || '') +
                    String(loc.hash || '') });
        finish(true);
      };
      channel.postMessage({ type: 'continue', state: state, nonce: nonce });
    });
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
    // WHO IT IS FOR (#508), from the ID Token the token endpoint answered
    // this page directly. Read, not verified: it is compared with the one
    // this page signed in with, never trusted for anything the API decides.
    const subject = SpaClient.subjectOf(json.id_token);
    if (subject) {
      this.subject = subject;
    }
  }

  /**
   * The `sub` of an ID Token, read without verifying it.
   *
   * @param idToken - the compact JWT, or nothing
   * @returns the subject, or ''
   */
  static subjectOf(idToken: Json): string {
    return SpaClient.claimOf(idToken, 'sub');
  }

  /**
   * A string claim of an ID Token, read without verifying it.
   *
   * @param idToken - the compact JWT, or nothing
   * @param name - the claim
   * @returns its value, or ''
   */
  static claimOf(idToken: Json, name: string): string {
    const parts = String(idToken || '').split('.');
    if (parts.length !== 3) {
      return '';
    }
    try {
      const text = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      return String(JSON.parse(text)[name] || '');
    } catch (e) {
      // Not a JWT this page can read: no claim, which a sign-in again
      // then treats as a different person, and a nonce check as a refusal.
      return '';
    }
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

  // ---------------------------------------------------------------------------
  // A WRITE SCOPE, ASKED FOR WHEN A WRITE NEEDS IT (#2168, ASVS 5.0.0 10.2.3).
  //
  // rcbj's decision: the console, the portal and the reports application
  // sign in with READ scopes only. The first time a write needs a write
  // scope, the application gets it through a SECOND AUTHORIZATION — silent
  // (`prompt=none`) while the sign-on session holds, and for a scope in
  // `freshScopes` (`admin:security`) a FRESH sign-in: silent only if the
  // session authenticated within FRESH_MAX_AGE_S (`max_age`), a new sign-in
  // (`prompt=login`, `max_age=0`) otherwise — and keeps the read token for
  // reading.
  //
  //   * THE SERVER SAYS WHICH SCOPE. A 403 carrying RFC 6750 section 3.1's
  //     `insufficient_scope` challenge names it (`insufficientScopeOf()`);
  //     the application keeps no table of its own. Only the scopes it may
  //     ask for (`writeScopes`) start a step, so a refusal no step can mend
  //     is drawn as it always was.
  //   * TWO TOKENS. The read token is kept and refreshed as before. A write
  //     token, per resource, is used for every method but GET while it
  //     lives, and is NEVER refreshed: the second authorization's refresh
  //     token is not kept, and the token is dropped at its own expiry or
  //     after WRITE_HOLD_MS, whichever is first. The next write after that
  //     steps again, silently while the session holds.
  //   * IN A POPUP. `/oauth2/authorize` forbids framing on every answer
  //     (`frame-ancestors 'none'`, which must stay), so the request goes in
  //     a window of its own, opened straight after the refusal — within the
  //     click that sent the write, which is what lets a browser open it.
  //     Its callback hands the code back over STEP_CHANNEL and closes
  //     (`handBackStepUp()`); this page redeems it with its own verifier and
  //     DPoP key, so the write token is bound to the same key as the read
  //     one. A bar over the page says what is happening, and offers the
  //     button that opens the window where a browser blocked it or a sign-in
  //     is needed, and Cancel.
  //   * THE WRITE WAITING ON IT STAYS IN MEMORY: it is the caller's own
  //     closure, awaiting `stepUp()`, and is sent once more when it answers
  //     true. Nothing about it is written to storage. Only where the browser
  //     has no window to open or no channel to hear the answer on does the
  //     page leave (`leaveForStepUp()`), and that loses the write, which
  //     each runtime says.
  // ---------------------------------------------------------------------------
  /**
   * The state prefix that marks a second authorization's callback.
   */
  static readonly STEP_STATE_PREFIX = 'step.';
  /**
   * The channel a second authorization's callback answers on.
   */
  static readonly STEP_CHANNEL = 'sts-spa-step';
  /**
   * The longest a write token is used, in milliseconds, whatever its own
   * lifetime.
   */
  static readonly WRITE_HOLD_MS = 10 * 60 * 1000;
  /**
   * How long before a write token's end it is no longer sent, in
   * milliseconds.
   */
  static readonly WRITE_EARLY_MS = 30 * 1000;
  /**
   * How recent a sign-in a scope in `freshScopes` asks for before a person is
   * asked to sign in again, in seconds (`max_age`).
   */
  static readonly FRESH_MAX_AGE_S = 300;
  /**
   * The authorization errors a silent step answers that a sign-in in the
   * window can mend (OpenID Connect Core section 3.1.2.6).
   */
  static readonly INTERACTION_ERRORS: string[] = ['login_required',
    'interaction_required', 'consent_required', 'account_selection_required'];

  /**
   * The scopes a 403's `insufficient_scope` challenge names (RFC 6750
   * section 3.1), or none for any other answer.
   *
   * @param res - a fetch response
   * @returns the scope values named
   */
  static insufficientScopeOf(res: Json): string[] {
    if (!res || res.status !== 403 || !res.headers ||
        typeof res.headers.get !== 'function') {
      return [];
    }
    const challenge = String(res.headers.get('WWW-Authenticate') || '');
    if (!/error="insufficient_scope"/.test(challenge)) {
      return [];
    }
    const named = /scope="([^"]*)"/.exec(challenge);
    return named ? named[1].split(/\s+/).filter(Boolean) : [];
  }

  /**
   * The write token for a resource while it may still be sent, or ''.
   *
   * @param resource - the resource indicator the token is audienced to
   * @returns the token, or ''
   */
  writeTokenFor(resource: string): string {
    const grant = this.writeGrants[String(resource)];
    const now = this.env.now ? this.env.now() : Date.now();
    if (!grant || now > grant.expiresAt - SpaClient.WRITE_EARLY_MS) {
      delete this.writeGrants[String(resource)];
      return '';
    }
    return grant.token;
  }

  /**
   * The token a request is sent with: a GET's is always the read token,
   * anything else the write token for its resource while one is held.
   *
   * @param method - the request's method
   * @param resource - the resource indicator
   * @returns the token, or '' where none is held
   */
  tokenFor(method: string, resource: string): string {
    const verb = String(method || 'GET').toUpperCase();
    if (verb === 'GET' || verb === 'HEAD') {
      return this.accessToken;
    }
    return this.writeTokenFor(resource) || this.accessToken;
  }

  /**
   * Stops using a write token: it was refused, or a sign-in replaced it.
   *
   * @param resource - the resource indicator, or nothing for every one
   * @returns nothing
   */
  dropWriteToken(resource?: string): void {
    if (resource === undefined) {
      this.writeGrants = {};
      return;
    }
    delete this.writeGrants[String(resource)];
  }

  /**
   * The scopes a write token for a resource carries, while it is held.
   *
   * @param resource - the resource indicator
   * @returns the scope values
   */
  writeScopesHeld(resource: string): string[] {
    return this.writeTokenFor(resource)
      ? this.writeGrants[String(resource)].scopes.slice(0) : [];
  }

  /**
   * The words of the step's bar, in English. A runtime with a translator
   * overrides this with its catalog's.
   *
   * @returns `{ pending, blocked, signIn, fresh, open, cancel, refused,
   *   other, failed }`
   */
  stepWords(): Json {
    return {
      pending: 'Getting permission to make this change…',
      blocked: 'This change needs your permission. Open the window to ' +
        'give it.',
      signIn: 'Sign in to make this change.',
      fresh: 'This change needs you to sign in again.',
      open: 'Continue',
      cancel: 'Cancel',
      refused: 'Permission to make this change was not given: ',
      other: 'That sign-in was another account, so nothing was sent.',
      failed: 'Permission to make this change could not be had.'
    };
  }

  // THE RUNTIME'S HALF of a step. Each application has its own client
  // registration, callback and way of signing in; these are the three
  // things a step asks of it, and the base answers nothing.
  /**
   * The application's authorization request, with `extra` added: `scope`,
   * `prompt`, `max_age`.
   *
   * @param state - the state
   * @param verifier - the PKCE verifier
   * @param extra - what this request adds or replaces
   * @returns the URL
   */
  async authorizeUrl(state: string, verifier: string,
                     extra?: Json): Promise<string> {
    void state;
    void verifier;
    void extra;
    return '';
  }

  /**
   * The application's callback, the step's `redirect_uri`.
   *
   * @returns the URL
   */
  callbackUrl(): string {
    return '';
  }

  /**
   * Where a browser with no window or no channel goes instead: a sign-in
   * on this page, asking for `scope`. It loses the write waiting.
   *
   * @param scope - the scope to sign in with
   * @param prompt - `login`, or '' for none
   * @returns nothing
   */
  async leaveForStepUp(scope: string, prompt: string): Promise<void> {
    void scope;
    void prompt;
  }

  /**
   * At the application's callback in a step's window: hands the answer to
   * the page that opened it and closes, redeeming nothing.
   *
   * @param query - the opened authorization response
   * @param path - the callback's path, which the address is put back to
   * @returns whether this was a step's callback
   */
  handBackStepUp(query: Json, path: string): boolean {
    const state = String((query && query.state) || '');
    if (state.indexOf(SpaClient.STEP_STATE_PREFIX) !== 0) {
      return false;
    }
    const win = this.env.window;
    if (this.env.history) {
      // The code leaves the address bar at once.
      this.env.history.replaceState(null, '', path);
    }
    const BC = win && win.BroadcastChannel;
    if (typeof BC === 'function') {
      const channel = new BC(SpaClient.STEP_CHANNEL);
      channel.postMessage({ state: state,
                            code: String(query.code || ''),
                            iss: String(query.iss || ''),
                            error: String(query.error || ''),
                            error_description:
                              String(query.error_description || '') });
      channel.close();
    }
    if (win && typeof win.close === 'function') {
      win.close();
    }
    return true;
  }

  /**
   * Gets a write token carrying the scopes a refusal named, by a second
   * authorization, and keeps it for its resource.
   *
   * @param resource - the resource indicator the write was for
   * @param named - the scopes the refusal named
   * @param fresh - whether a fresh sign-in is asked for whatever is named
   * @returns true when a write token carrying every scope asked for is held
   *   and the write may be sent again; false otherwise
   */
  async stepUp(resource: string, named: string[],
               fresh?: boolean): Promise<boolean> {
    const self = this;
    // ONE AT A TIME: a second write waits for the step in progress, and
    // then asks again only for what it did not bring.
    while (this.stepping) {
      await this.stepping;
    }
    const wanted = (named || []).filter(function (one: string): boolean {
      return self.writeScopes.indexOf(one) >= 0;
    });
    if (!wanted.length || !this.subject) {
      return false;
    }
    const held = this.writeScopesHeld(resource);
    if (!fresh && wanted.every(function (one: string): boolean {
      return held.indexOf(one) >= 0;
    })) {
      return true;
    }
    const step = this.stepOnce(resource, wanted, held, !!fresh);
    this.stepping = step;
    try {
      return await step;
    } finally {
      this.stepping = null;
    }
  }

  /**
   * One second authorization, the body of `stepUp()`.
   *
   * @param resource - the resource indicator
   * @param wanted - the scopes asked for
   * @param held - the scopes the write token in hand carries
   * @param fresh - whether a fresh sign-in is asked for
   * @returns whether a write token carrying every scope asked for is held
   */
  async stepOnce(resource: string, wanted: string[], held: string[],
                 fresh: boolean): Promise<boolean> {
    const self = this;
    // FOUR KINDS OF REQUEST. `silent` (`prompt=none`) for an ordinary write
    // scope, answered out of the session; `recent` (`prompt=none`,
    // `max_age=FRESH_MAX_AGE_S`) for a scope in `freshScopes`, answered out
    // of the session only if it authenticated within that window
    // (OpenID Connect Core section 3.1.2.1), so a person who has just signed
    // in is not asked twice; and, where the session cannot answer either,
    // `signIn` (no prompt) and `fresh` (`prompt=login`, `max_age=0`), which
    // ask something of the person in the window. A step after RFC 9470's
    // `insufficient_user_authentication` (#1538) starts at `fresh`: the
    // server has said the sign-in is too old for its own window.
    const must = wanted.some(function (one: string): boolean {
      return self.freshScopes.indexOf(one) >= 0;
    });
    // THE READ SCOPES, THE ELEVATION ALREADY HELD AND THE ONE ASKED FOR, so
    // one write token serves every write on the resource; issuance still
    // narrows it to the roles held.
    const scopes: string[] = [];
    String(this.scope || '').split(/\s+/).concat(held, wanted)
      .forEach(function (one: string) {
        if (one && scopes.indexOf(one) < 0) {
          scopes.push(one);
        }
      });
    const scope = scopes.join(' ');
    const win = this.env.window;
    const BC = win && win.BroadcastChannel;
    if (!win || typeof win.open !== 'function' || typeof BC !== 'function') {
      await this.leaveForStepUp(scope, must || fresh ? 'login' : '');
      return false;
    }
    const words = this.stepWords();
    const channel = new BC(SpaClient.STEP_CHANNEL);
    let request: Json = null;
    const prepare = async function (kind: string): Promise<void> {
      const verifier = self.random(32);
      const state = SpaClient.STEP_STATE_PREFIX + self.random(16);
      const extra: Json = { scope: scope };
      if (kind === 'silent' || kind === 'recent') {
        extra.prompt = 'none';
      }
      if (kind === 'recent') {
        extra.max_age = String(SpaClient.FRESH_MAX_AGE_S);
      }
      if (kind === 'fresh') {
        extra.prompt = 'login';
        extra.max_age = '0';
      }
      request = { verifier: verifier, state: state, kind: kind,
                  silent: kind === 'silent' || kind === 'recent',
                  url: await self.authorizeUrl(state, verifier, extra) };
    };
    try {
      await prepare(fresh ? 'fresh' : (must ? 'recent' : 'silent'));
      let answered: Json = null;
      for (let round = 0; round < 3 && !answered; round++) {
        const outcome = await this.awaitStepAnswer(channel, request, words,
          request.silent ? words.pending
            : (request.kind === 'fresh' ? words.fresh : words.signIn));
        if (!outcome || outcome.cancelled) {
          return false;
        }
        if (outcome.error) {
          // A SILENT STEP THE SESSION CANNOT ANSWER: a sign-in in the
          // window, which the person opens with the bar's button — a fresh
          // one where a recent one was asked for.
          if (request.silent && SpaClient.INTERACTION_ERRORS.indexOf(
              String(outcome.error)) >= 0) {
            await prepare(request.kind === 'recent' ? 'fresh' : 'signIn');
            continue;
          }
          this.drawStepBar(words.refused + String(outcome.error_description ||
            outcome.error), null);
          return false;
        }
        answered = outcome;
      }
      if (!answered || !answered.code ||
          !await this.issuerMatches(answered)) {
        this.drawStepBar(words.failed, null);
        return false;
      }
      const answer = await this.tokenRequest({
        grant_type: 'authorization_code', code: String(answered.code),
        redirect_uri: this.callbackUrl(), client_id: this.clientId,
        code_verifier: request.verifier, resource: resource });
      if (answer.aborted) {
        return false;
      }
      if (answer.status !== 200 || !answer.json.access_token ||
          !await this.nonceMatches(answer.json.id_token, request.verifier)) {
        this.drawStepBar(words.failed, null);
        return false;
      }
      // THE TAB'S PERSON, AND NOBODY ELSE: a write token for another
      // account is not kept, and the write waiting is not sent.
      if (!SpaClient.answerIsFor(this.subject, answer.json.id_token)) {
        this.drawStepBar(words.other, null);
        return false;
      }
      const granted = String(answer.json.scope || scope).split(/\s+/)
        .filter(Boolean);
      const now = this.env.now ? this.env.now() : Date.now();
      // NO REFRESH TOKEN IS KEPT: the write token ends with its own life.
      this.writeGrants[String(resource)] = {
        token: String(answer.json.access_token),
        expiresAt: Math.min(
          now + (Number(answer.json.expires_in) || 300) * 1000,
          now + SpaClient.WRITE_HOLD_MS),
        scopes: granted };
      this.removeStepBar();
      return wanted.every(function (one: string): boolean {
        return granted.indexOf(one) >= 0;
      });
    } finally {
      channel.close();
    }
  }

  /**
   * Opens the step's window, or offers to, and waits for its callback's
   * answer or the person's Cancel.
   *
   * @param channel - the channel the callback answers on
   * @param request - `{ state, url }`
   * @param words - `stepWords()`
   * @param message - what the bar says meanwhile
   * @returns the answer `{ code, iss, error, error_description }`, or
   *   `{ cancelled: true }`
   */
  awaitStepAnswer(channel: Json, request: Json, words: Json,
                  message: string): Promise<Json> {
    const self = this;
    return new Promise(function (resolve) {
      let done = false;
      const finish = function (value: Json): void {
        if (done) {
          return;
        }
        done = true;
        channel.onmessage = null;
        resolve(value);
      };
      channel.onmessage = function (event: Json) {
        const data = event && event.data;
        if (!data || String(data.state || '') !== request.state) {
          return;
        }
        finish(data);
      };
      const open = function (): boolean {
        const popup = self.env.window.open(request.url, 'sts-step',
                                           'popup,width=560,height=760');
        return !!popup;
      };
      // A SILENT STEP IS OPENED AT ONCE, while the click that sent the write
      // still lets a window open. A sign-in waits for the button: it asks
      // something of the person, who should see why first.
      const opened = request.silent ? open() : false;
      self.drawStepBar(opened ? message
                              : (request.silent ? words.blocked : message),
        { open: opened ? null : function () {
            if (open()) {
              self.drawStepBar(message, { cancel: function () {
                finish({ cancelled: true });
              } });
            }
          },
          cancel: function () {
            finish({ cancelled: true });
          } });
    });
  }

  /**
   * Draws the step's bar over the page, which stays as it is under it.
   *
   * @param message - what it says
   * @param actions - `{ open, cancel }`, each a function or null; null for
   *   a bar that only says something and closes with its button
   * @returns nothing
   */
  drawStepBar(message: string, actions: Json): void {
    const doc = this.env.document;
    if (!doc || typeof doc.createElement !== 'function' || !doc.body) {
      return;
    }
    const words = this.stepWords();
    let bar = doc.getElementById ? doc.getElementById('step-bar') : null;
    if (!bar) {
      bar = doc.createElement('div');
      bar.id = 'step-bar';
      bar.className = 'reauth';
      if (typeof bar.setAttribute === 'function') {
        bar.setAttribute('role', 'alertdialog');
        bar.setAttribute('aria-live', 'polite');
      }
      doc.body.appendChild(bar);
    }
    const self = this;
    const acts = actions || { cancel: function () {
      self.removeStepBar();
    } };
    const esc = WebMessages.WebMessages.esc;
    WebSafeDom.render(bar, '<span>' + esc(message) + '</span> ' +
      (acts.open ? '<button type="button" data-step="open">' +
                   esc(words.open) + '</button> ' : '') +
      (acts.cancel ? '<button type="button" data-step="cancel">' +
                     esc(words.cancel) + '</button>' : ''));
    // THE CLICK OPENS THE WINDOW in its own task, as a browser asks.
    bar.onclick = function (event: Json) {
      const target = event && event.target;
      const which = target && typeof target.getAttribute === 'function'
        ? String(target.getAttribute('data-step') || '') : '';
      if (which && typeof acts[which] === 'function') {
        acts[which]();
      }
    };
    this.stepActions = acts;
  }

  /**
   * What the step's bar's buttons do, for a test that presses one.
   */
  stepActions: Json = null;

  /**
   * Takes the step's bar away.
   *
   * @returns nothing
   */
  removeStepBar(): void {
    const doc = this.env.document;
    const bar = doc && doc.getElementById
      ? doc.getElementById('step-bar') : null;
    if (bar && bar.parentNode) {
      bar.parentNode.removeChild(bar);
    }
    this.stepActions = null;
  }
}

export = SpaClient;
