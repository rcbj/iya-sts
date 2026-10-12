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
//   * this realm's address for a path (`url()`), the authorization server
//     and the sign-out included where they are on another listener (#472).
//
// What each application does with a page — routing, drawing, its forms —
// stays in its own runtime (`web_runtime.ts`, `portal/web_portal_runtime.ts`).
//
// A `web_` MODULE, on `web_kit.ts`'s terms: it requires nothing, logs
// nothing, and is bundled for a browser by `build-typescript.sh`. Everything
// it touches in the browser arrives in `env`, so a test drives it in node.
// ---------------------------------------------------------------------------

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
}

/**
 * A static application's OAuth 2.0 client: PKCE, DPoP and the tokens.
 */
class SpaClient {
  protected env: Json;
  protected prefix: string;
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
  // WHERE THE AUTHORIZATION SERVER, THE API AND THE SIGN-IN SERVICE ARE when
  // they are not on this application's own listener (#472): their bases, the
  // realm prefix included, from the shell's `data-sts-*` attributes; '' where
  // they are here, which is every service without a custom listener.
  protected elsewhere: Json;
  // The realm's authorization server metadata, read once (`asMetadata()`).
  protected metadata: Json;

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
    this.env = env;
    this.prefix = prefix;
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
    const root = env.document && env.document.documentElement;
    const read = function (name: string): string {
      return root && typeof root.getAttribute === 'function'
        ? String(root.getAttribute(name) || '').replace(/\/+$/, '') : '';
    };
    const elsewhere: Json = {};
    Object.keys(options.elsewhere || {}).forEach(function (first) {
      elsewhere[first] = read(options.elsewhere[first]);
    });
    this.elsewhere = elsewhere;
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

  /**
   * This realm's address for one of its paths.
   *
   * @param path - `/oauth2/token`, `/admin-api/...`
   * @returns the absolute URL
   */
  url(path: string): string {
    const elsewhere = this.elsewhere || {};
    const first = '/' + String(path || '').split(/[/?#]/)[1];
    if (elsewhere[first]) {
      return elsewhere[first] + path;
    }
    return this.env.location.origin + this.prefix + path;
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

  // ---------------------------------------------------------------------------
  // PUSHED AUTHORIZATION REQUESTS (RFC 9126), WHERE THE REALM REQUIRES THEM
  // (#568). FAPI 2.0 makes PAR the only way to send an authorization request,
  // and a realm may require it on its own (`oauth2.requirePar`). The server-
  // rendered surfaces pushed through `oidc_rp.ts`; a static one pushes from
  // the browser: its parameters POSTed to the PAR endpoint the metadata names
  // — a public client authenticates with nothing, as section 2 allows — with a
  // DPoP proof, and the browser sent to the authorization endpoint with the
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
        this.url('/.well-known/oauth-authorization-server'),
        { headers: { 'Accept': 'application/json' } });
      json = res.status === 200 ? await res.json() : {};
    } catch (e) {
      // No metadata: the ordinary request, which a realm that requires PAR
      // refuses in words the page draws.
      json = {};
    }
    this.metadata = json || {};
    return this.metadata;
  }

  /**
   * The authorization request's URL: pushed first where the realm requires
   * it, the query otherwise.
   *
   * @param params - the request's parameters, `client_id` among them
   * @returns the URL to send the browser to
   */
  async authorizationRequestUrl(params: Json): Promise<string> {
    const authorize = this.url('/oauth2/authorize');
    const meta = await this.asMetadata();
    if (meta.require_pushed_authorization_requests !== true) {
      return authorize + '?' + new URLSearchParams(params).toString();
    }
    const endpoint = String(meta.pushed_authorization_request_endpoint ||
                            this.url('/oauth2/par'));
    for (let attempt = 0; attempt < 2; attempt++) {
      const res = await this.env.fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded',
                   'DPoP': await this.proof('POST', endpoint, '') },
        body: new URLSearchParams(params).toString() });
      this.keepNonce(res);
      const json = await res.json().catch(function () {
        return {};
      });
      if (res.status === 400 && json.error === 'use_dpop_nonce' &&
          attempt === 0) {
        continue;
      }
      if (res.status === 201 && json.request_uri) {
        return authorize + '?' + new URLSearchParams({
          client_id: String(params.client_id || this.clientId),
          request_uri: String(json.request_uri) }).toString();
      }
      break;
    }
    // A REFUSED PUSH: the ordinary request, which the authorization endpoint
    // then refuses with the reason, drawn where the person can read it.
    return authorize + '?' + new URLSearchParams(params).toString();
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
    const parts = String(idToken || '').split('.');
    if (parts.length !== 3) {
      return '';
    }
    try {
      const text = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
      return String(JSON.parse(text).sub || '');
    } catch (e) {
      // Not a JWT this page can read: no subject, which a sign-in again
      // then treats as a different person.
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
}

export = SpaClient;
